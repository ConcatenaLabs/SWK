//! The engine's errors. Each says why, in words a wallet can show.

/// Why the engine refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The descriptor breaks the specification, or its sources do not give it.
    #[error("descriptor refused: {0}")]
    Descriptor(String),
    /// The instance does not fit the template.
    #[error("instance refused: {0}")]
    Instance(String),
    /// The spend cannot be built as asked.
    #[error("spend refused: {0}")]
    Spend(String),
    /// The contract's program refuses the transaction.
    #[error("the contract's program refuses this transaction: {0}")]
    Program(String),
    /// The engine cannot say what an input or output of the transaction does.
    #[error("refused: {0}")]
    Unaccounted(String),
    /// The chain would refuse the transaction now.
    #[error("refused: {0}")]
    Chain(String),
    /// A five-point signing rule does not hold.
    #[error("not signed: {0}")]
    Signing(String),
}
