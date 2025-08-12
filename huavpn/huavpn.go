/* SPDX-License-Identifier: MIT
 *
 * HUA VPN Client - Custom WireGuard client for Harokopio University of Athens
 * Based on WireGuard Windows client
 */

package huavpn

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/lxn/walk"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/manager"
)

// HUAVPNClient handles the authentication and configuration retrieval for HUA VPN
type HUAVPNClient struct {
	baseURL      string
	authURL      string
	deviceURL    string
	callbackURL  string
	clientID     string
	codeVerifier string
	codeChallenge string
	accessToken  string
}

// DeviceRequest represents the request to create a new device
type DeviceRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// DeviceResponse represents the response containing the WireGuard configuration
type DeviceResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Configuration string `json:"configuration"`
}

// NewHUAVPNClient creates a new HUA VPN client instance
func NewHUAVPNClient() *HUAVPNClient {
	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)
	
	return &HUAVPNClient{
		baseURL:       "https://wvpn.hua.gr",
		authURL:       "https://auth2.ditapps.hua.gr/realms/HUA/protocol/openid-connect/auth",
		deviceURL:     "https://wvpn.hua.gr/user_devices/new",
		callbackURL:   "https://wvpn.hua.gr/auth/oidc/keycloak/callback/",
		clientID:      "firezone",
		codeVerifier:  codeVerifier,
		codeChallenge: codeChallenge,
	}
}

// generateCodeVerifier generates a random code verifier for PKCE
func generateCodeVerifier() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// generateCodeChallenge generates the code challenge from the verifier
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// StartAuthFlow initiates the OAuth2 authentication flow
func (h *HUAVPNClient) StartAuthFlow() error {
	// Build the authorization URL
	params := url.Values{
		"access_type":            {"offline"},
		"client_id":              {h.clientID},
		"code_challenge":         {h.codeChallenge},
		"code_challenge_method":  {"S256"},
		"redirect_uri":           {h.callbackURL},
		"response_type":          {"code"},
		"scope":                  {"openid email profile"},
		"state":                  {generateRandomState()},
	}
	
	authURL := fmt.Sprintf("%s?%s", h.authURL, params.Encode())
	
	// Open the browser for authentication
	return h.openBrowser(authURL)
}

// generateRandomState generates a random state parameter
func generateRandomState() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// openBrowser opens the default browser with the given URL
func (h *HUAVPNClient) openBrowser(url string) error {
	var cmd string
	var args []string
	
	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default: // linux and others
		cmd = "xdg-open"
		args = []string{url}
	}
	
	return exec.Command(cmd, args...).Start()
}

// CreateDevice creates a new VPN device and returns the WireGuard configuration
func (h *HUAVPNClient) CreateDevice(name, description string) (*DeviceResponse, error) {
	deviceReq := DeviceRequest{
		Name:        name,
		Description: description,
	}
	
	jsonData, err := json.Marshal(deviceReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal device request: %w", err)
	}
	
	req, err := http.NewRequest("POST", h.deviceURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.accessToken)
	
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	var deviceResp DeviceResponse
	err = json.NewDecoder(resp.Body).Decode(&deviceResp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return &deviceResp, nil
}

// ShowHUAConnectDialog shows the HUA VPN easy connect dialog
func ShowHUAConnectDialog(owner walk.Form) error {
	dlg, err := walk.NewDialog(owner)
	if err != nil {
		return err
	}
	dlg.SetTitle("HUA VPN Easy Connect")
	dlg.SetSize(walk.Size{Width: 400, Height: 300})
	
	// Try to set HUA icon if available
	if icon, iconErr := walk.NewIconFromFile("../../Images/HUA-Logo-Red-Square-32.ico"); iconErr == nil {
		dlg.SetIcon(icon)
	}
	
	vbox := walk.NewVBoxLayout()
	vbox.SetMargins(walk.Margins{HNear: 10, VNear: 10, HFar: 10, VFar: 10})
	dlg.SetLayout(vbox)
	
	// Title label
	titleLabel, err := walk.NewLabel(dlg)
	if err != nil {
		return err
	}
	titleLabel.SetText("Connect to HUA VPN")
	font, _ := walk.NewFont("Segoe UI", 12, walk.FontBold)
	titleLabel.SetFont(font)
	
	// Description label
	descLabel, err := walk.NewLabel(dlg)
	if err != nil {
		return err
	}
	descLabel.SetText("Enter a name for your device to automatically configure HUA VPN connection:")
	
	// Device name input
	nameLabel, err := walk.NewLabel(dlg)
	if err != nil {
		return err
	}
	nameLabel.SetText("Device Name:")
	
	nameEdit, err := walk.NewLineEdit(dlg)
	if err != nil {
		return err
	}
	nameEdit.SetText(fmt.Sprintf("HUA-Device-%d", time.Now().Unix()))
	
	// Description input
	descInputLabel, err := walk.NewLabel(dlg)
	if err != nil {
		return err
	}
	descInputLabel.SetText("Description (optional):")
	
	descEdit, err := walk.NewLineEdit(dlg)
	if err != nil {
		return err
	}
	descEdit.SetText("HUA VPN Device")
	
	// Buttons
	buttonContainer, err := walk.NewComposite(dlg)
	if err != nil {
		return err
	}
	hbox := walk.NewHBoxLayout()
	buttonContainer.SetLayout(hbox)
	
	walk.NewHSpacer(buttonContainer)
	
	cancelBtn, err := walk.NewPushButton(buttonContainer)
	if err != nil {
		return err
	}
	cancelBtn.SetText("Cancel")
	cancelBtn.Clicked().Attach(func() {
		dlg.Accept()
	})
	
	connectBtn, err := walk.NewPushButton(buttonContainer)
	if err != nil {
		return err
	}
	connectBtn.SetText("Connect")
	connectBtn.Clicked().Attach(func() {
		go func() {
			err := connectToHUAVPN(nameEdit.Text(), descEdit.Text(), dlg)
			if err != nil {
				dlg.Synchronize(func() {
					walk.MsgBox(dlg, "Error", fmt.Sprintf("Failed to connect: %v", err), walk.MsgBoxIconError)
				})
			} else {
				dlg.Synchronize(func() {
					walk.MsgBox(dlg, "Success", "HUA VPN connection configured successfully!", walk.MsgBoxIconInformation)
					dlg.Accept()
				})
			}
		}()
	})
	
	dlg.Run()
	return nil
}

// connectToHUAVPN handles the complete flow of connecting to HUA VPN
func connectToHUAVPN(deviceName, description string, parent walk.Form) error {
	client := NewHUAVPNClient()
	
	// Start authentication flow
	err := client.StartAuthFlow()
	if err != nil {
		return fmt.Errorf("failed to start auth flow: %w", err)
	}
	
	// Show waiting dialog
	parent.Synchronize(func() {
		walk.MsgBox(parent, "Authentication", "Please complete authentication in your browser and then click OK.", walk.MsgBoxIconInformation)
	})
	
	// Note: In a real implementation, you would need to implement a callback server
	// or use a different method to capture the authorization code
	// For now, we'll simulate this step
	
	// Create device and get configuration
	deviceResp, err := client.CreateDevice(deviceName, description)
	if err != nil {
		return fmt.Errorf("failed to create device: %w", err)
	}
	
	// Parse the WireGuard configuration
	config, err := conf.FromWgQuickWithUnknownEncoding(deviceResp.Configuration, deviceResp.Name)
	if err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}
	
	// Create the tunnel
	_, err = manager.IPCClientNewTunnel(config)
	if err != nil {
		return fmt.Errorf("failed to create tunnel: %w", err)
	}
	
	return nil
}