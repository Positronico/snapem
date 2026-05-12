package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/positronico/snapem/internal/config"
	"github.com/positronico/snapem/internal/errors"
	"github.com/positronico/snapem/internal/scanner/cache"
	"github.com/positronico/snapem/internal/ui"
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Inspect or clear the scan result cache",
	Long: `snapem caches scan results from Socket.dev and Google OSV under your
user cache directory so repeat scans against unchanged dependencies don't
re-hit the upstream APIs. Use these subcommands to see what's cached and
to wipe it if you want a fresh fetch.`,
}

var cacheInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show cache location, entry count, and size",
	RunE:  runCacheInfo,
}

var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Delete every cached scan result",
	RunE:  runCacheClear,
}

func init() {
	cacheCmd.AddCommand(cacheInfoCmd)
	cacheCmd.AddCommand(cacheClearCmd)
	rootCmd.AddCommand(cacheCmd)
}

func runCacheInfo(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return errors.ConfigError(err.Error())
	}
	display := ui.New(cfg.UI.Verbose, cfg.UI.Quiet, useColor(cfg.UI.Color, noColor))

	dir := cfg.Scanning.Cache.Directory
	display.Print(fmt.Sprintf("Cache directory: %s", dir))
	display.Print(fmt.Sprintf("TTL: %s", cfg.Scanning.Cache.TTL))
	display.Print(fmt.Sprintf("Enabled: %v", cfg.Scanning.Cache.Enabled))

	store := &cache.FileStore{Dir: dir}
	stats, err := store.Stat()
	if err != nil {
		display.Warning(fmt.Sprintf("Could not read cache: %v", err))
		return nil
	}
	display.Print(fmt.Sprintf("Entries: %d", stats.Entries))
	display.Print(fmt.Sprintf("Bytes: %d", stats.Bytes))
	return nil
}

func runCacheClear(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return errors.ConfigError(err.Error())
	}
	display := ui.New(cfg.UI.Verbose, cfg.UI.Quiet, useColor(cfg.UI.Color, noColor))

	store := &cache.FileStore{Dir: cfg.Scanning.Cache.Directory}
	deleted, err := store.Clear()
	if err != nil {
		display.Error(fmt.Sprintf("Failed to clear cache: %v", err))
		return errors.New(errors.ExitGeneralError, "cache clear failed")
	}
	display.Success(fmt.Sprintf("Cleared %d cache entries", deleted))
	return nil
}
