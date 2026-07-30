#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
#include <mqtt_protocol.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define AUTHN_PREFIX "rss.authn.v1."
#define AUTHN_VERSION_KEY AUTHN_PREFIX "version"
#define AUTHN_PRINCIPAL_KEY AUTHN_PREFIX "principal"
#define AUTHN_SIGNATURE_KEY AUTHN_PREFIX "signature"
#define PRINCIPAL_PREFIX "urn:rss:mqtt-device:v1:"
#define PRINCIPAL_CAPACITY 160U
#define TOPIC_CAPACITY 256U
#define ED25519_SIGNATURE_BYTES 64U

static const unsigned char SIGNING_DOMAIN[] = "rss.mqtt.authn.v1";

struct plugin_state {
    mosquitto_plugin_id_t *identifier;
    EVP_PKEY *signing_key;
};

struct device_principal {
    char value[PRINCIPAL_CAPACITY];
    const char *tenant;
    const char *device;
    const char *generation;
};

static bool canonical_uuid(const char *value)
{
    for (size_t index = 0; index < 36U; ++index) {
        const bool hyphen = index == 8U || index == 13U || index == 18U || index == 23U;
        if (hyphen) {
            if (value[index] != '-') {
                return false;
            }
        } else if (!((value[index] >= '0' && value[index] <= '9') ||
                     (value[index] >= 'a' && value[index] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static bool canonical_generation(const char *value)
{
    if (value[0] < '1' || value[0] > '9') {
        return false;
    }
    size_t length = 1U;
    while (value[length] != '\0') {
        if (value[length] < '0' || value[length] > '9' || length >= 20U) {
            return false;
        }
        ++length;
    }

    errno = 0;
    char *end = NULL;
    (void)strtoull(value, &end, 10);
    return errno == 0 && end != NULL && *end == '\0';
}

static bool parse_principal(struct device_principal *principal)
{
    const size_t prefix_length = sizeof(PRINCIPAL_PREFIX) - 1U;
    if (strncmp(principal->value, PRINCIPAL_PREFIX, prefix_length) != 0) {
        return false;
    }

    char *tenant = principal->value + prefix_length;
    char *device = tenant + 37U;
    char *generation = device + 37U;
    if (strlen(tenant) < 75U || tenant[36] != ':' || device[36] != ':' ||
        !canonical_uuid(tenant) || !canonical_uuid(device) ||
        !canonical_generation(generation)) {
        return false;
    }

    principal->tenant = tenant;
    principal->device = device;
    principal->generation = generation;
    return true;
}

static bool certificate_principal(
    const struct mosquitto *client,
    struct device_principal *principal)
{
    X509 *certificate = mosquitto_client_certificate(client);
    if (certificate == NULL) {
        return false;
    }

    GENERAL_NAMES *names = X509_get_ext_d2i(certificate, NID_subject_alt_name, NULL, NULL);
    bool valid = names != NULL;
    size_t uri_count = 0U;
    if (names != NULL) {
        const int count = sk_GENERAL_NAME_num(names);
        for (int index = 0; index < count; ++index) {
            const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, index);
            if (name == NULL || name->type != GEN_URI) {
                continue;
            }
            ++uri_count;
            const ASN1_IA5STRING *uri = name->d.uniformResourceIdentifier;
            const int length = ASN1_STRING_length(uri);
            const unsigned char *bytes = ASN1_STRING_get0_data(uri);
            if (uri_count != 1U || length <= 0 || (size_t)length >= sizeof(principal->value) ||
                bytes == NULL || memchr(bytes, '\0', (size_t)length) != NULL) {
                valid = false;
                continue;
            }
            memcpy(principal->value, bytes, (size_t)length);
            principal->value[length] = '\0';
        }
        GENERAL_NAMES_free(names);
    }
    X509_free(certificate);

    return valid && uri_count == 1U && parse_principal(principal);
}

static bool exact_topic_for_direction(
    const struct device_principal *principal,
    const char *direction,
    const char *const *contracts,
    size_t contract_count,
    const char *topic)
{
    char expected[TOPIC_CAPACITY];
    for (size_t index = 0; index < contract_count; ++index) {
        const int length = snprintf(
            expected,
            sizeof(expected),
            "rss/v1/%.*s/%.*s/%s/%s/%s",
            36,
            principal->tenant,
            36,
            principal->device,
            principal->generation,
            direction,
            contracts[index]);
        if (length > 0 && (size_t)length < sizeof(expected) && strcmp(expected, topic) == 0) {
            return true;
        }
    }
    return false;
}

static bool exact_uplink_topic(const struct device_principal *principal, const char *topic)
{
    static const char *const contracts[] = {
        "identity.device-command-acked",
        "identity.device-certificate-reported",
    };
    return exact_topic_for_direction(
        principal, "uplink", contracts, sizeof(contracts) / sizeof(contracts[0]), topic);
}

static bool exact_downlink_topic(const struct device_principal *principal, const char *topic)
{
    static const char *const contracts[] = {
        "identity.commands.apply-device-certificate",
    };
    return exact_topic_for_direction(
        principal, "downlink", contracts, sizeof(contracts) / sizeof(contracts[0]), topic);
}

static bool device_topic_allowed(const struct device_principal *principal, int access, const char *topic)
{
    if (topic == NULL) {
        return false;
    }
    switch (access) {
    case MOSQ_ACL_WRITE:
        return exact_uplink_topic(principal, topic);
    case MOSQ_ACL_READ:
    case MOSQ_ACL_SUBSCRIBE:
        return exact_downlink_topic(principal, topic);
    case MOSQ_ACL_UNSUBSCRIBE:
        return exact_downlink_topic(principal, topic) || exact_uplink_topic(principal, topic);
    default:
        return false;
    }
}

static bool has_reserved_property(const mosquitto_property *properties)
{
    for (const mosquitto_property *property = properties; property != NULL;
         property = mosquitto_property_next(property)) {
        if (mosquitto_property_identifier(property) != MQTT_PROP_USER_PROPERTY) {
            continue;
        }
        char *name = NULL;
        char *value = NULL;
        const mosquitto_property *found = mosquitto_property_read_string_pair(
            property, MQTT_PROP_USER_PROPERTY, &name, &value, false);
        if (found == NULL || name == NULL || value == NULL) {
            free(name);
            free(value);
            return true;
        }
        const bool reserved = strncmp(name, AUTHN_PREFIX, sizeof(AUTHN_PREFIX) - 1U) == 0;
        free(name);
        free(value);
        if (reserved) {
            return true;
        }
    }
    return false;
}

static bool correlation_data(
    const mosquitto_property *properties,
    unsigned char **value,
    uint16_t *length)
{
    size_t count = 0U;
    for (const mosquitto_property *property = properties; property != NULL;
         property = mosquitto_property_next(property)) {
        if (mosquitto_property_identifier(property) == MQTT_PROP_CORRELATION_DATA) {
            ++count;
        }
    }
    if (count > 1U) {
        return false;
    }
    if (count == 0U) {
        *value = NULL;
        *length = 0U;
        return true;
    }
    return mosquitto_property_read_binary(
               properties,
               MQTT_PROP_CORRELATION_DATA,
               (void **)value,
               length,
               false) != NULL;
}

static bool append_field(
    unsigned char **cursor,
    const unsigned char *end,
    const void *value,
    uint32_t length)
{
    const size_t remaining = (size_t)(end - *cursor);
    if (remaining < 4U + (size_t)length || (length > 0U && value == NULL)) {
        return false;
    }
    (*cursor)[0] = (unsigned char)(length >> 24U);
    (*cursor)[1] = (unsigned char)(length >> 16U);
    (*cursor)[2] = (unsigned char)(length >> 8U);
    (*cursor)[3] = (unsigned char)length;
    *cursor += 4U;
    if (length > 0U) {
        memcpy(*cursor, value, length);
        *cursor += length;
    }
    return true;
}

static int sign_message(
    const struct plugin_state *state,
    const struct device_principal *principal,
    const struct mosquitto_evt_message *message,
    const unsigned char *correlation,
    uint16_t correlation_length,
    char encoded_signature[89])
{
    unsigned char payload_digest[EVP_MAX_MD_SIZE];
    unsigned int payload_digest_length = 0U;
    const void *payload = message->payloadlen == 0U ? "" : message->payload;
    if (payload == NULL ||
        EVP_Digest(
            payload,
            message->payloadlen,
            payload_digest,
            &payload_digest_length,
            EVP_sha256(),
            NULL) != 1 ||
        payload_digest_length != 32U) {
        return MOSQ_ERR_INVAL;
    }

    const size_t principal_length = strlen(principal->value);
    const size_t topic_length = strlen(message->topic);
    const size_t capacity = sizeof(SIGNING_DOMAIN) + 4U * 7U + 1U + principal_length +
                            topic_length + correlation_length + 32U + 1U + 1U;
    unsigned char *canonical = malloc(capacity);
    if (canonical == NULL) {
        return MOSQ_ERR_NOMEM;
    }
    unsigned char *cursor = canonical;
    const unsigned char *end = canonical + capacity;
    memcpy(cursor, SIGNING_DOMAIN, sizeof(SIGNING_DOMAIN));
    cursor += sizeof(SIGNING_DOMAIN);
    const unsigned char qos = message->qos;
    const unsigned char retain = message->retain ? 1U : 0U;
    const bool canonical_ok =
        append_field(&cursor, end, "1", 1U) &&
        append_field(&cursor, end, principal->value, (uint32_t)principal_length) &&
        append_field(&cursor, end, message->topic, (uint32_t)topic_length) &&
        append_field(&cursor, end, correlation, correlation_length) &&
        append_field(&cursor, end, payload_digest, 32U) &&
        append_field(&cursor, end, &qos, 1U) && append_field(&cursor, end, &retain, 1U) &&
        cursor == end;
    if (!canonical_ok) {
        free(canonical);
        return MOSQ_ERR_INVAL;
    }

    unsigned char signature[ED25519_SIGNATURE_BYTES];
    size_t signature_length = sizeof(signature);
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    const bool signed_ok = context != NULL &&
                           EVP_DigestSignInit(context, NULL, NULL, NULL, state->signing_key) == 1 &&
                           EVP_DigestSign(
                               context,
                               signature,
                               &signature_length,
                               canonical,
                               capacity) == 1 &&
                           signature_length == ED25519_SIGNATURE_BYTES;
    EVP_MD_CTX_free(context);
    free(canonical);
    if (!signed_ok) {
        return MOSQ_ERR_INVAL;
    }

    const int encoded_length = EVP_EncodeBlock(
        (unsigned char *)encoded_signature,
        signature,
        (int)signature_length);
    if (encoded_length != 88) {
        return MOSQ_ERR_INVAL;
    }
    for (int index = 0; index < encoded_length; ++index) {
        if (encoded_signature[index] == '+') {
            encoded_signature[index] = '-';
        } else if (encoded_signature[index] == '/') {
            encoded_signature[index] = '_';
        }
    }
    encoded_signature[86] = '\0';
    return MOSQ_ERR_SUCCESS;
}

static int reject_message(struct mosquitto_evt_message *message)
{
    message->reason_code = MQTT_RC_NOT_AUTHORIZED;
    return MOSQ_ERR_ACL_DENIED;
}

static int on_acl_check(int event, void *event_data, void *userdata)
{
    (void)userdata;
    if (event != MOSQ_EVT_ACL_CHECK || event_data == NULL) {
        return MOSQ_ERR_INVAL;
    }
    struct mosquitto_evt_acl_check *check = event_data;
    if (check->client == NULL || check->topic == NULL) {
        return MOSQ_ERR_ACL_DENIED;
    }

    struct device_principal principal = {0};
    if (!certificate_principal(check->client, &principal)) {
        /* RSS service identities have no device URI SAN; defer to static acl_file. */
        return MOSQ_ERR_PLUGIN_DEFER;
    }
    if (!device_topic_allowed(&principal, check->access, check->topic)) {
        return MOSQ_ERR_ACL_DENIED;
    }
    return MOSQ_ERR_SUCCESS;
}

static int on_message(int event, void *event_data, void *userdata)
{
    if (event != MOSQ_EVT_MESSAGE || event_data == NULL || userdata == NULL) {
        return MOSQ_ERR_INVAL;
    }
    struct mosquitto_evt_message *message = event_data;
    const struct plugin_state *state = userdata;
    if (message->client == NULL || message->topic == NULL ||
        has_reserved_property(message->properties)) {
        return reject_message(message);
    }

    if (strstr(message->topic, "/uplink/") == NULL) {
        return MOSQ_ERR_SUCCESS;
    }

    struct device_principal principal = {0};
    if (!certificate_principal(message->client, &principal) ||
        !exact_uplink_topic(&principal, message->topic)) {
        return reject_message(message);
    }

    unsigned char *correlation = NULL;
    uint16_t correlation_length = 0U;
    if (!correlation_data(message->properties, &correlation, &correlation_length)) {
        free(correlation);
        return reject_message(message);
    }
    char signature[89] = {0};
    const int sign_result = sign_message(
        state,
        &principal,
        message,
        correlation,
        correlation_length,
        signature);
    free(correlation);
    if (sign_result != MOSQ_ERR_SUCCESS) {
        return sign_result;
    }

    if (mosquitto_property_add_string_pair(
            &message->properties, MQTT_PROP_USER_PROPERTY, AUTHN_VERSION_KEY, "1") !=
            MOSQ_ERR_SUCCESS ||
        mosquitto_property_add_string_pair(
            &message->properties,
            MQTT_PROP_USER_PROPERTY,
            AUTHN_PRINCIPAL_KEY,
            principal.value) != MOSQ_ERR_SUCCESS ||
        mosquitto_property_add_string_pair(
            &message->properties,
            MQTT_PROP_USER_PROPERTY,
            AUTHN_SIGNATURE_KEY,
            signature) != MOSQ_ERR_SUCCESS) {
        return MOSQ_ERR_NOMEM;
    }
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_version(int supported_version_count, const int *supported_versions)
{
    for (int index = 0; index < supported_version_count; ++index) {
        if (supported_versions[index] == MOSQ_PLUGIN_VERSION) {
            return MOSQ_PLUGIN_VERSION;
        }
    }
    return -1;
}

int mosquitto_plugin_init(
    mosquitto_plugin_id_t *identifier,
    void **userdata,
    struct mosquitto_opt *options,
    int option_count)
{
    if (identifier == NULL || userdata == NULL || options == NULL || option_count != 1 ||
        options[0].key == NULL || options[0].value == NULL ||
        strcmp(options[0].key, "signing_key") != 0) {
        return MOSQ_ERR_INVAL;
    }
    FILE *key_file = fopen(options[0].value, "r");
    if (key_file == NULL) {
        return MOSQ_ERR_INVAL;
    }
    EVP_PKEY *signing_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (signing_key == NULL || EVP_PKEY_base_id(signing_key) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(signing_key);
        return MOSQ_ERR_INVAL;
    }

    struct plugin_state *state = calloc(1U, sizeof(*state));
    if (state == NULL) {
        EVP_PKEY_free(signing_key);
        return MOSQ_ERR_NOMEM;
    }
    state->identifier = identifier;
    state->signing_key = signing_key;
    const int acl_result = mosquitto_callback_register(
        identifier, MOSQ_EVT_ACL_CHECK, on_acl_check, NULL, state);
    if (acl_result != MOSQ_ERR_SUCCESS) {
        EVP_PKEY_free(state->signing_key);
        free(state);
        return acl_result;
    }
    const int message_result = mosquitto_callback_register(
        identifier, MOSQ_EVT_MESSAGE, on_message, NULL, state);
    if (message_result != MOSQ_ERR_SUCCESS) {
        (void)mosquitto_callback_unregister(
            identifier, MOSQ_EVT_ACL_CHECK, on_acl_check, NULL);
        EVP_PKEY_free(state->signing_key);
        free(state);
        return message_result;
    }
    *userdata = state;
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *userdata, struct mosquitto_opt *options, int option_count)
{
    (void)options;
    (void)option_count;
    struct plugin_state *state = userdata;
    if (state == NULL) {
        return MOSQ_ERR_SUCCESS;
    }
    (void)mosquitto_callback_unregister(
        state->identifier, MOSQ_EVT_ACL_CHECK, on_acl_check, NULL);
    const int result = mosquitto_callback_unregister(
        state->identifier, MOSQ_EVT_MESSAGE, on_message, NULL);
    EVP_PKEY_free(state->signing_key);
    free(state);
    return result;
}
