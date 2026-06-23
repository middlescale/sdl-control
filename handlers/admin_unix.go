package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"sdl-control/control"

	log "github.com/sirupsen/logrus"
)

func StartAdminUnixServer(ctx context.Context, ctrl *control.Controller, socketPath string, version string) error {
	if strings.TrimSpace(socketPath) == "" {
		return nil
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		return err
	}
	log.Infof("admin unix socket listening on %s", socketPath)
	var closeOnce sync.Once
	closeListener := func() {
		closeOnce.Do(func() {
			_ = ln.Close()
			_ = os.Remove(socketPath)
		})
	}
	go func() {
		<-ctx.Done()
		closeListener()
	}()
	go func() {
		defer closeListener()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					log.Warnf("admin unix socket temporary accept error: %v", err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				log.Errorf("admin unix socket accept loop stopped: %v", err)
				return
			}
			go handleAdminConn(ctrl, version, conn)
		}
	}()
	return nil
}

func handleAdminConn(ctrl *control.Controller, version string, conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) == 0 {
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: "invalid request"})
		return
	}
	var req adminRequest
	if err := json.Unmarshal(line, &req); err != nil {
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: "invalid json"})
		return
	}
	_ = json.NewEncoder(conn).Encode(executeAdminRequest(ctrl, version, req))
}

func selectUpdatedDeviceViews(updated []control.UMAuthDevice, devices []control.DeviceAdminView) []control.DeviceAdminView {
	if len(updated) == 0 {
		return nil
	}
	deviceByKey := make(map[string]control.DeviceAdminView, len(devices))
	for _, device := range devices {
		deviceByKey[device.Group+"\x00"+device.DeviceID] = device
	}
	updatedViews := make([]control.DeviceAdminView, 0, len(updated))
	for _, record := range updated {
		key := record.GroupName + "\x00" + record.DeviceID
		if device, ok := deviceByKey[key]; ok {
			updatedViews = append(updatedViews, device)
			continue
		}
		name := strings.TrimSpace(record.DisplayName)
		if name == "" {
			name = record.DeviceID
		}
		updatedViews = append(updatedViews, control.DeviceAdminView{
			UserID:           record.UserID,
			Group:            record.GroupName,
			Name:             name,
			DeviceID:         record.DeviceID,
			AuthedAtUnix:     record.AuthedAt.Unix(),
			AuthExpireAtUnix: record.AuthExpireAt.Unix(),
			AuthExpired:      !record.AuthExpireAt.IsZero() && time.Now().After(record.AuthExpireAt),
			UpdatedAtUnix:    record.AuthedAt.Unix(),
		})
	}
	return updatedViews
}
