// Minimal stubs for validation-free build in this repository.
// Provides IsBlockMutated used by compact block reconstruction.

#include <primitives/block.h>

// In this trimmed build we don't perform mutation checks; return false.
bool IsBlockMutated(const CBlock& /*block*/, bool /*check_witness_root*/)
{
    return false;
}
