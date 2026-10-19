CREATE TABLE rss_timeseries.samples (
 tenant_id uuid NOT NULL, namespace text COLLATE "C" NOT NULL,
 source text COLLATE "C" NOT NULL, generation text COLLATE "C" NOT NULL, sample_id text COLLATE "C" NOT NULL,
 observed_at bigint NOT NULL, sequence numeric(20,0) NOT NULL CHECK (sequence BETWEEN 0 AND 18446744073709551615),
 series_digest bytea NOT NULL CHECK (octet_length(series_digest)=32),
 key text COLLATE "C" NOT NULL, version numeric(20,0) NOT NULL,
 subject text COLLATE "C" NOT NULL, resource text COLLATE "C" NOT NULL,
 raw bytea NOT NULL CHECK (octet_length(raw) BETWEEN 1 AND 4194304), received_at bigint NOT NULL CHECK (received_at>=0),
 PRIMARY KEY (tenant_id,namespace,source,generation,sample_id,observed_at),
 FOREIGN KEY (tenant_id,namespace,source,generation,sample_id,observed_at) REFERENCES rss_timeseries.sample_identities(tenant_id,namespace,source,generation,sample_id,observed_at),
 FOREIGN KEY (tenant_id,namespace,key,version) REFERENCES rss_timeseries.definitions
)