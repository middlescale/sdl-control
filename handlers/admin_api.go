package handlers

import (
	"encoding/json"
	"strings"
	"time"

	"sdl-control/control"
	"sdl-control/util"

	log "github.com/sirupsen/logrus"
)

func executeAdminRequest(ctrl *control.Controller, version string, req adminRequest) adminResponse {
	switch req.Action {
	case "version":
		return adminResponse{OK: true, Version: strings.TrimSpace(version)}
	case "create_user":
		user, err := ctrl.UMCreateUserWithID(strings.TrimSpace(req.UserID), strings.TrimSpace(req.Group), strings.TrimSpace(req.Domain))
		if err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		return adminResponse{OK: true, UserID: user.UserID, Name: user.Name, Domain: user.Domain}
	case "list_users":
		users, err := ctrl.UMListUsers(strings.TrimSpace(req.IDFilter), strings.TrimSpace(req.NameFilter))
		if err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		return adminResponse{OK: true, Users: users}
	case "issue_device_ticket", "issue_auth_ticket":
		group := strings.TrimSpace(req.Group)
		if group == "" {
			group = "default.ms.net"
		}
		ttl := req.TTLSeconds
		if ttl <= 0 {
			ttl = 300
		}
		t, err := ctrl.UMIssueDeviceTicket(strings.TrimSpace(req.UserID), group, time.Duration(ttl)*time.Second)
		if err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		return adminResponse{OK: true, Ticket: t.Ticket, ExpireAtUnix: t.ExpireAt.Unix()}
	case "register_gateway", "gateway_enlist":
		gatewayID := strings.TrimSpace(req.GatewayID)
		if gatewayID == "" {
			return adminResponse{OK: false, Error: "gateway_id required"}
		}
		if err := ctrl.ApproveGatewayNodeByID(gatewayID); err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		if pushPackets, pushErr := ctrl.BuildPushDeviceListPacketsForGatewayChangeIfNeeded(); pushErr != nil {
			log.Errorf("BuildPushDeviceListPacketsForGatewayChangeIfNeeded error: %v", pushErr)
		} else {
			for _, push := range pushPackets {
				if push == nil || push.DstIP == nil {
					continue
				}
				if err := quicStreams.writeToRoute(push.RouteNetworkKey, util.IpToUint32(push.DstIP), push.Marshal()); err != nil {
					log.Warnf("PushDeviceList dispatch failed: %s err=%v", push.DstIP, err)
				}
			}
		}
		return adminResponse{OK: true}
	case "delist_gateway", "gateway_delist":
		gatewayID := strings.TrimSpace(req.GatewayID)
		if gatewayID == "" {
			return adminResponse{OK: false, Error: "gateway_id required"}
		}
		if err := ctrl.DelistGatewayNodeByID(gatewayID); err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		if pushPackets, pushErr := ctrl.BuildPushDeviceListPacketsForGatewayChangeIfNeeded(); pushErr != nil {
			log.Errorf("BuildPushDeviceListPacketsForGatewayChangeIfNeeded error: %v", pushErr)
		} else {
			for _, push := range pushPackets {
				if push == nil || push.DstIP == nil {
					continue
				}
				if err := quicStreams.writeToRoute(push.RouteNetworkKey, util.IpToUint32(push.DstIP), push.Marshal()); err != nil {
					log.Warnf("PushDeviceList dispatch failed: %s err=%v", push.DstIP, err)
				}
			}
		}
		return adminResponse{OK: true}
	case "list_gateway", "gateway_list":
		return adminResponse{OK: true, Gateways: ctrl.ListGateways()}
	case "exit_node_list":
		return adminResponse{OK: true, ExitNodes: ctrl.ListExitNodes(strings.TrimSpace(req.UserID))}
	case "exit_node_approve":
		userID, deviceID, err := ctrl.ApproveExitNodeTarget(
			strings.TrimSpace(req.UserID),
			strings.TrimSpace(req.DeviceID),
			strings.TrimSpace(req.Name),
		)
		if err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		if pushPackets, pushErr := ctrl.BuildPushDeviceListPacketsForAuthedDeviceChange(userID, deviceID); pushErr != nil {
			log.Errorf("BuildPushDeviceListPacketsForAuthedDeviceChange error: %v", pushErr)
		} else {
			for _, push := range pushPackets {
				if push == nil || push.DstIP == nil {
					continue
				}
				if err := quicStreams.writeToRoute(push.RouteNetworkKey, util.IpToUint32(push.DstIP), push.Marshal()); err != nil {
					log.Warnf("PushDeviceList dispatch failed: %s err=%v", push.DstIP, err)
				}
			}
		}
		return adminResponse{OK: true, ExitNodes: ctrl.ListExitNodes(userID)}
	case "exit_node_revoke":
		if err := ctrl.RevokeExitNode(strings.TrimSpace(req.UserID), strings.TrimSpace(req.DeviceID)); err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		if pushPackets, pushErr := ctrl.BuildPushDeviceListPacketsForAuthedDeviceChange(strings.TrimSpace(req.UserID), strings.TrimSpace(req.DeviceID)); pushErr != nil {
			log.Errorf("BuildPushDeviceListPacketsForAuthedDeviceChange error: %v", pushErr)
		} else {
			for _, push := range pushPackets {
				if push == nil || push.DstIP == nil {
					continue
				}
				if err := quicStreams.writeToRoute(push.RouteNetworkKey, util.IpToUint32(push.DstIP), push.Marshal()); err != nil {
					log.Warnf("PushDeviceList dispatch failed: %s err=%v", push.DstIP, err)
				}
			}
		}
		return adminResponse{OK: true, ExitNodes: ctrl.ListExitNodes(strings.TrimSpace(req.UserID))}
	case "list_device", "list_devices":
		userID := strings.TrimSpace(req.UserID)
		if userID == "" {
			return adminResponse{OK: false, Error: "user_id required"}
		}
		return adminResponse{OK: true, Devices: ctrl.ListDevices(userID)}
	case "extend_device_expiry":
		userID := strings.TrimSpace(req.UserID)
		if userID == "" {
			return adminResponse{OK: false, Error: "user_id required"}
		}
		ttl := req.TTLSeconds
		if ttl <= 0 {
			ttl = int64((30 * 24 * time.Hour).Seconds())
		}
		updated, err := ctrl.UMExtendAuthedDeviceExpiry(
			userID,
			strings.TrimSpace(req.Group),
			strings.TrimSpace(req.DeviceID),
			time.Duration(ttl)*time.Second,
			req.All,
		)
		if err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		devices := ctrl.ListDevices(userID)
		return adminResponse{
			OK:             true,
			Devices:        devices,
			UpdatedDevices: selectUpdatedDeviceViews(updated, devices),
			UpdatedCount:   len(updated),
		}
	case "delete_device":
		userID := strings.TrimSpace(req.UserID)
		if userID == "" {
			return adminResponse{OK: false, Error: "user_id required"}
		}
		deleted, err := ctrl.DeleteAuthedDevice(userID, strings.TrimSpace(req.Group), strings.TrimSpace(req.DeviceID))
		if err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		if pushPackets, pushErr := ctrl.BuildPushDeviceListPacketsForGatewayChange(); pushErr != nil {
			log.Errorf("BuildPushDeviceListPacketsForGatewayChange error: %v", pushErr)
		} else {
			for _, push := range pushPackets {
				if push == nil || push.DstIP == nil {
					continue
				}
				if err := quicStreams.writeToRoute(push.RouteNetworkKey, util.IpToUint32(push.DstIP), push.Marshal()); err != nil {
					log.Warnf("PushDeviceList dispatch failed: %s err=%v", push.DstIP, err)
				}
			}
		}
		devices := ctrl.ListDevices(userID)
		return adminResponse{
			OK:             true,
			Devices:        devices,
			UpdatedDevices: selectUpdatedDeviceViews(deleted, devices),
			UpdatedCount:   len(deleted),
		}
	case "rename_device":
		userID := strings.TrimSpace(req.UserID)
		if userID == "" {
			return adminResponse{OK: false, Error: "user_id required"}
		}
		renamed, err := ctrl.RenameAuthedDevice(userID, strings.TrimSpace(req.Group), strings.TrimSpace(req.DeviceID), strings.TrimSpace(req.Name))
		if err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		if pushPackets, pushErr := ctrl.BuildPushDeviceListPacketsForGatewayChange(); pushErr != nil {
			log.Errorf("BuildPushDeviceListPacketsForGatewayChange error: %v", pushErr)
		} else {
			for _, push := range pushPackets {
				if push == nil || push.DstIP == nil {
					continue
				}
				if err := quicStreams.writeToRoute(push.RouteNetworkKey, util.IpToUint32(push.DstIP), push.Marshal()); err != nil {
					log.Warnf("PushDeviceList dispatch failed: %s err=%v", push.DstIP, err)
				}
			}
		}
		devices := ctrl.ListDevices(userID)
		return adminResponse{
			OK:             true,
			Devices:        devices,
			UpdatedDevices: selectUpdatedDeviceViews([]control.UMAuthDevice{renamed}, devices),
			UpdatedCount:   1,
		}
	case "dns_domains":
		return adminResponse{OK: true, Domains: ctrl.ListDNSDomains()}
	case "dns_snapshot":
		domain := strings.TrimSpace(req.Domain)
		snapshot, err := ctrl.BuildDNSSnapshot(domain, strings.TrimSpace(req.Group))
		if err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		return adminResponse{OK: true, DNSSnapshot: snapshot}
	case "collect_debug":
		timeoutSec := req.TimeoutSec
		if timeoutSec <= 0 {
			timeoutSec = 10
		}
		packet, targetIP, requestID, err := ctrl.PrepareDebugCollectByName(
			strings.TrimSpace(req.Name),
			strings.TrimSpace(req.UserID),
			strings.TrimSpace(req.Group),
			req.Sections,
		)
		if err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		if err := quicStreams.writeToRoute(packet.RouteNetworkKey, targetIP, packet.Marshal()); err != nil {
			ctrl.CancelDebugCollect(requestID)
			return adminResponse{OK: false, Error: err.Error()}
		}
		result, err := ctrl.AwaitDebugCollect(requestID, time.Duration(timeoutSec)*time.Second)
		if err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		raw := json.RawMessage(result.SnapshotJSON)
		if !json.Valid(raw) {
			raw, err = json.Marshal(map[string]string{"raw": result.SnapshotJSON})
			if err != nil {
				return adminResponse{OK: false, Error: err.Error()}
			}
		}
		return adminResponse{OK: true, DebugResult: raw, DebugPath: result.SavedPath}
	case "start_debug_watch":
		timeoutSec := req.TimeoutSec
		if timeoutSec <= 0 {
			timeoutSec = 10
		}
		durationSec := req.DurationSec
		if durationSec <= 0 {
			durationSec = 300
		}
		packet, targetIP, requestID, err := ctrl.PrepareDebugWatchStartByName(
			strings.TrimSpace(req.Name),
			strings.TrimSpace(req.UserID),
			strings.TrimSpace(req.Group),
			req.Sections,
			time.Duration(durationSec)*time.Second,
		)
		if err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		if err := quicStreams.writeToRoute(packet.RouteNetworkKey, targetIP, packet.Marshal()); err != nil {
			ctrl.CancelDebugWatchStart(requestID)
			return adminResponse{OK: false, Error: err.Error()}
		}
		result, err := ctrl.AwaitDebugWatchStart(requestID, time.Duration(timeoutSec)*time.Second)
		if err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		return adminResponse{OK: true, DebugWatchID: result.WatchID, DebugPath: result.SavedPath}
	case "stop_debug_watch":
		timeoutSec := req.TimeoutSec
		if timeoutSec <= 0 {
			timeoutSec = 10
		}
		packet, targetIP, requestID, err := ctrl.PrepareDebugWatchStopByName(
			strings.TrimSpace(req.Name),
			strings.TrimSpace(req.UserID),
			strings.TrimSpace(req.Group),
		)
		if err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		if err := quicStreams.writeToRoute(packet.RouteNetworkKey, targetIP, packet.Marshal()); err != nil {
			ctrl.CancelDebugWatchStop(requestID)
			return adminResponse{OK: false, Error: err.Error()}
		}
		result, err := ctrl.AwaitDebugWatchStop(requestID, time.Duration(timeoutSec)*time.Second)
		if err != nil {
			return adminResponse{OK: false, Error: err.Error()}
		}
		return adminResponse{OK: true, DebugWatchID: result.WatchID, DebugPath: result.SavedPath}
	default:
		return adminResponse{OK: false, Error: "unsupported action"}
	}
}
