from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
import hashlib
import uuid
import time
import warnings


class MigrationStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class DeprecationLevel(Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


@dataclass
class AlgorithmInfo:
    algorithm_name: str
    implementation: Callable
    version: str
    deprecation_level: DeprecationLevel = DeprecationLevel.ACTIVE
    replacement_algorithm: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EncryptedRecord:
    record_id: str
    algorithm_used: str
    ciphertext: bytes
    key_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MigrationPlan:
    migration_id: str
    old_algorithm: str
    new_algorithm: str
    affected_records: List[EncryptedRecord]
    batch_size: int = 100
    created_at: float = field(default_factory=time.time)
    status: MigrationStatus = MigrationStatus.PENDING
    progress: int = 0  # number of records migrated


@dataclass
class MigrationResult:
    migration_id: str
    status: MigrationStatus
    records_migrated: int
    records_failed: int
    execution_time: float
    completed_at: Optional[float] = None


class AlgorithmRegistry:
    """Registry for cryptographic algorithm implementations."""

    def __init__(self):
        self._algorithms: Dict[str, AlgorithmInfo] = {}
        self._deprecated_warnings: Dict[str, bool] = {}

    def register(self, algorithm_info: AlgorithmInfo) -> None:
        """Register a new algorithm implementation."""
        self._algorithms[algorithm_info.algorithm_name] = algorithm_info
        if algorithm_info.deprecation_level == DeprecationLevel.DEPRECATED:
            self._emit_deprecation_warning(algorithm_info)

    def get(self, algorithm_name: str) -> Optional[AlgorithmInfo]:
        """Retrieve algorithm by name."""
        return self._algorithms.get(algorithm_name)

    def list_algorithms(self) -> List[str]:
        """List all registered algorithms."""
        return list(self._algorithms.keys())

    def mark_deprecated(self, algorithm_name: str, replacement: Optional[str] = None) -> None:
        """Mark algorithm as deprecated."""
        algo = self._algorithms.get(algorithm_name)
        if algo:
            algo.deprecation_level = DeprecationLevel.DEPRECATED
            algo.replacement_algorithm = replacement
            self._emit_deprecation_warning(algo)

    def mark_retired(self, algorithm_name: str) -> None:
        """Mark algorithm as retired (no longer supported)."""
        algo = self._algorithms.get(algorithm_name)
        if algo:
            algo.deprecation_level = DeprecationLevel.RETIRED

    def _emit_deprecation_warning(self, algo: AlgorithmInfo) -> None:
        """Emit deprecation warning for algorithm."""
        if algo.algorithm_name not in self._deprecated_warnings:
            replacement_msg = f" Use {algo.replacement_algorithm} instead." if algo.replacement_algorithm else ""
            msg = f"Algorithm '{algo.algorithm_name}' is deprecated.{replacement_msg}"
            warnings.warn(msg, DeprecationWarning, stacklevel=3)
            self._deprecated_warnings[algo.algorithm_name] = True


class CryptoAgilityFramework:
    """Manages cryptographic algorithm implementations and migrations.

    Features:
    - Register algorithm implementations
    - Track algorithm deprecation
    - Plan data re-encryption migrations
    - Execute and rollback migrations
    - Emit deprecation warnings

    For production: integrate with KMS for key rotation, integrate with actual
    cryptographic implementations, and add transaction support for rollbacks.
    """

    def __init__(self):
        self.registry = AlgorithmRegistry()
        self._data_store: Dict[str, EncryptedRecord] = {}
        self._migration_plans: Dict[str, MigrationPlan] = {}
        self._migration_snapshots: Dict[str, List[EncryptedRecord]] = {}
        self._migration_history: List[MigrationResult] = []

    def register_algorithm_implementation(self, algorithm_name: str, implementation: Callable, version: str = "1.0") -> None:
        """Register a new cryptographic algorithm implementation."""
        algo_info = AlgorithmInfo(
            algorithm_name=algorithm_name,
            implementation=implementation,
            version=version,
            deprecation_level=DeprecationLevel.ACTIVE,
        )
        self.registry.register(algo_info)

    def store_encrypted_record(self, record_id: str, algorithm: str, ciphertext: bytes, key_id: str) -> None:
        """Store an encrypted record for later migration."""
        record = EncryptedRecord(record_id=record_id, algorithm_used=algorithm, ciphertext=ciphertext, key_id=key_id)
        self._data_store[record_id] = record

    def migrate_to_new_algorithm(self, old_algorithm: str, new_algorithm: str) -> MigrationPlan:
        """Plan a migration from one algorithm to another.

        Scans data store for records using the old algorithm and creates a migration plan.
        """
        # verify algorithms exist
        old_algo = self.registry.get(old_algorithm)
        new_algo = self.registry.get(new_algorithm)
        if not old_algo or not new_algo:
            raise ValueError(f"Algorithm not found: old={old_algorithm}, new={new_algorithm}")

        # check if old algorithm is retired
        if old_algo.deprecation_level == DeprecationLevel.RETIRED:
            warnings.warn(f"Algorithm '{old_algorithm}' is retired; migration is mandatory.", DeprecationWarning)

        # collect affected records
        affected_records = [rec for rec in self._data_store.values() if rec.algorithm_used == old_algorithm]

        migration_id = str(uuid.uuid4())
        plan = MigrationPlan(
            migration_id=migration_id,
            old_algorithm=old_algorithm,
            new_algorithm=new_algorithm,
            affected_records=affected_records,
        )
        self._migration_plans[migration_id] = plan
        # snapshot data for potential rollback
        self._migration_snapshots[migration_id] = [rec for rec in affected_records]
        return plan

    def execute_algorithm_migration(self, plan: MigrationPlan) -> MigrationResult:
        """Execute a migration plan: re-encrypt all affected records.

        For each record with old algorithm, simulate decryption and re-encryption with new algorithm.
        """
        migration_id = plan.migration_id
        start_time = time.time()
        records_migrated = 0
        records_failed = 0

        try:
            plan.status = MigrationStatus.IN_PROGRESS
            old_algo = self.registry.get(plan.old_algorithm)
            new_algo = self.registry.get(plan.new_algorithm)

            for i, record in enumerate(plan.affected_records):
                try:
                    # simulate decryption (in production: decrypt with old key/algorithm)
                    # decrypted_data = old_algo.implementation(record.ciphertext, decrypt=True)
                    decrypted_data = hashlib.sha256(record.ciphertext).digest()

                    # simulate re-encryption with new algorithm
                    # new_ciphertext = new_algo.implementation(decrypted_data, encrypt=True)
                    new_ciphertext = hashlib.sha256(decrypted_data + b"_new").digest()

                    # update record in store
                    updated_record = EncryptedRecord(
                        record_id=record.record_id,
                        algorithm_used=plan.new_algorithm,
                        ciphertext=new_ciphertext,
                        key_id=record.key_id,
                        metadata=record.metadata,
                    )
                    self._data_store[record.record_id] = updated_record
                    records_migrated += 1
                    plan.progress = i + 1

                except Exception as e:
                    records_failed += 1

            plan.status = MigrationStatus.COMPLETED
            execution_time = time.time() - start_time
            result = MigrationResult(
                migration_id=migration_id,
                status=MigrationStatus.COMPLETED,
                records_migrated=records_migrated,
                records_failed=records_failed,
                execution_time=execution_time,
                completed_at=time.time(),
            )
            self._migration_history.append(result)
            return result

        except Exception as e:
            plan.status = MigrationStatus.FAILED
            execution_time = time.time() - start_time
            result = MigrationResult(
                migration_id=migration_id,
                status=MigrationStatus.FAILED,
                records_migrated=records_migrated,
                records_failed=records_failed,
                execution_time=execution_time,
            )
            self._migration_history.append(result)
            return result

    def rollback_algorithm_migration(self, migration_id: str) -> bool:
        """Rollback a migration to the previous algorithm.

        Restores records from pre-migration snapshot.
        """
        plan = self._migration_plans.get(migration_id)
        snapshot = self._migration_snapshots.get(migration_id)

        if not plan or not snapshot:
            return False

        try:
            # restore records from snapshot
            for record in snapshot:
                self._data_store[record.record_id] = record

            plan.status = MigrationStatus.ROLLED_BACK
            return True
        except Exception:
            return False

    def deprecate_algorithm(self, algorithm_name: str, replacement: Optional[str] = None) -> None:
        """Deprecate an algorithm and suggest replacement."""
        self.registry.mark_deprecated(algorithm_name, replacement)

    def retire_algorithm(self, algorithm_name: str) -> None:
        """Retire an algorithm (no longer supported)."""
        self.registry.mark_retired(algorithm_name)

    def get_migration_history(self) -> List[MigrationResult]:
        """Get history of all migrations."""
        return self._migration_history

    def get_algorithm_status(self, algorithm_name: str) -> Optional[Dict[str, Any]]:
        """Get status and metadata of an algorithm."""
        algo = self.registry.get(algorithm_name)
        if not algo:
            return None
        return {
            "algorithm_name": algo.algorithm_name,
            "version": algo.version,
            "deprecation_level": algo.deprecation_level.value,
            "replacement_algorithm": algo.replacement_algorithm,
            "metadata": algo.metadata,
        }


__all__ = [
    "CryptoAgilityFramework",
    "AlgorithmRegistry",
    "AlgorithmInfo",
    "EncryptedRecord",
    "MigrationPlan",
    "MigrationResult",
    "MigrationStatus",
    "DeprecationLevel",
]
