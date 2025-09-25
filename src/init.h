// Placeholder header retained for compatibility with upstream include paths.
// The SV2 Template Provider no longer exposes node initialization helpers.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#endif // BITCOIN_INIT_H
bool AppInitLockDirectories();
/**
/**
 * Bitcoin core main initialization.
 * @note This should only be done after daemonization. Call Shutdown() if this function fails.
 * @pre Parameters should be parsed and config file should be read, AppInitLockDirectories should have been called.
 */
bool AppInitMain(node::NodeContext& node);

/**
 * Register all arguments with the ArgsManager
 */
void SetupServerArgs(ArgsManager& argsman, bool can_listen_ipc=false);

#endif // BITCOIN_INIT_H
