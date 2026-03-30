package main

import (
	"os"
	"syscall"
)

func fileIno(fi os.FileInfo) uint64 {
	stat := fi.Sys().(*syscall.Stat_t)
	return stat.Ino
}
