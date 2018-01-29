use acl::Acl;
use consts::CreateMode;
use data::Stat;

/// An operation that can exist as part of a transaction.
///
/// See `ZooKeeper.commit` for more information.
#[derive(Debug)]
pub enum Op {
    /// Check that the ZNode at `path` has the specified `version`. If the entry does not exist or
    /// has a different value than `version`, the transaction will fail.
    Check { path: String, version: Option<i32> },

    /// Create a node with the given `path`.
    ///
    /// See `ZooKeeper.create` for more information.
    Create { path: String, data: Vec<u8>, acl: Vec<Acl>, mode: CreateMode },

    /// Delete the node at the given `path`.
    ///
    /// See `ZooKeeper.delete` for more information.
    Delete { path: String, version: Option<i32> },

    /// Set the `data` for the node at the given `path`.
    ///
    /// See `ZooKeeper.set_data` for more information.
    SetData { path: String, data: Vec<u8>, version: Option<i32> },
}

/// Part of the response from the server as a result of a transaction. Each discriminant corresponds
/// to a discriminant in `Op`.
///
/// See `ZooKeeper.commit` for more information.
#[derive(Debug)]
pub enum OpResult {
    /// Result of `Op::Check` or `Op::Delete` -- no information.
    Empty,

    /// Result of `Op::Create` -- the `path` is the path of the created node, which is useful if the
    /// node was created with `CreateMode::PersistentSequential` or
    /// `CreateMode::EphemeralSequential`.
    Create { path: String },

    /// Result of `Op::SetData` -- the `stat` is the new `Stat` value of the node.
    SetData { stat: Stat },
}
