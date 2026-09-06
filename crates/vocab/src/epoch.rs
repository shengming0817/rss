//! CAS 与资源锁使用的单调 token 值；实际条件写由各 provider 校验。

/// 单调 fencing token（lease epoch）。
///
/// `u64` 内核 + `Ord`：资源版本 / 接管任期单调递增，由条件写 provider 校验。newtype funnel
/// （私有字段，单一构造入口 [`Epoch::new`]）——独立语义不复用裸 `u64`，杜绝把任意计数误当 fence token。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(u64);

impl Epoch {
    /// 由原始单调值构造 epoch。
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// 借出底层单调值（供 adapter 持久化 / wire 编码）。
    pub fn get(self) -> u64 {
        self.0
    }

    /// 下一个 epoch（接管 / 续租时单调 `+1`）；饱和于 `u64::MAX`（不回绕——回绕会破坏 fencing 单调性）。
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

#[cfg(test)]
mod tests {
    use super::Epoch;

    // new/get 往返 + 边界值（0 / MAX）。
    #[test]
    fn new_get_round_trips() {
        for v in [0_u64, 1, 42, u64::MAX] {
            assert_eq!(Epoch::new(v).get(), v, "round-trip v={v}");
        }
    }

    // next 单调 +1；MAX 处饱和（不回绕，保 fencing 单调）。
    #[test]
    fn next_is_monotonic_and_saturates() {
        assert_eq!(Epoch::new(0).next(), Epoch::new(1));
        assert_eq!(Epoch::new(41).next(), Epoch::new(42));
        // 饱和：MAX.next() 仍 MAX（回绕会让旧写绕过 CAS）。
        assert_eq!(Epoch::new(u64::MAX).next(), Epoch::new(u64::MAX));
    }

    // Ord：fencing CAS 依赖严格序（旧 < 新）。
    #[test]
    fn ord_total_and_strict() {
        assert!(Epoch::new(1) < Epoch::new(2));
        assert!(Epoch::new(2) > Epoch::new(1));
        assert_eq!(Epoch::new(5), Epoch::new(5));
        // 表驱动：单调链严格递增。
        let chain = [Epoch::new(0), Epoch::new(1), Epoch::new(2), Epoch::new(3)];
        for w in chain.windows(2) {
            assert!(w[0] < w[1], "{:?} !< {:?}", w[0], w[1]);
        }
    }

    // Copy + Hash + Debug 可用（供 HashMap key / 结构化日志）。
    #[test]
    fn copy_hash_debug() {
        let e = Epoch::new(7);
        let copied = e; // Copy：不 move
        assert_eq!(e, copied);
        let mut set = std::collections::HashSet::new();
        set.insert(e);
        assert!(set.contains(&copied));
        assert!(format!("{e:?}").contains('7'));
    }
}
