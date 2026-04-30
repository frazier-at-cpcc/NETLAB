/**
 * LabsConnect Console Client
 *
 * Unified console client supporting both VNC (via noVNC) and SPICE (via spice-html5)
 * for browser-based access to Proxmox VM consoles.
 */

class LabConsoleClient {
    constructor(options) {
        this.sessionId = options.sessionId;
        this.container = options.container;
        this.protocol = options.protocol || 'vnc';
        this.token = options.token || null;
        this.apiBaseUrl = options.apiBaseUrl || '';

        this.client = null;
        this.connected = false;
        this.connecting = false;

        // Event callbacks
        this.onConnect = options.onConnect || (() => {});
        this.onDisconnect = options.onDisconnect || (() => {});
        this.onError = options.onError || (() => {});
        this.onCredentialsRequired = options.onCredentialsRequired || (() => {});
        this.onClipboard = options.onClipboard || (() => {});
        this.onResize = options.onResize || (() => {});

        // VNC-specific options
        this.vncOptions = {
            scaleViewport: options.scaleViewport !== false,
            resizeSession: options.resizeSession || false,
            clipViewport: options.clipViewport || false,
            dragViewport: options.dragViewport || false,
            showDotCursor: options.showDotCursor || false,
            qualityLevel: options.qualityLevel || 6,
            compressionLevel: options.compressionLevel || 2
        };

        // SPICE-specific options
        this.spiceOptions = {
            enableAudio: options.enableAudio !== false,
            enableClipboard: options.enableClipboard !== false
        };
    }

    /**
     * Get console capabilities from the API
     */
    async getCapabilities() {
        const response = await this._fetch(`/api/session/${this.sessionId}/console`);
        return response;
    }

    /**
     * Connect to the console using the current protocol
     */
    async connect() {
        if (this.connecting || this.connected) {
            console.warn('Console client already connecting or connected');
            return;
        }

        this.connecting = true;

        try {
            if (this.protocol === 'vnc') {
                await this._connectVNC();
            } else if (this.protocol === 'spice') {
                await this._connectSPICE();
            } else {
                throw new Error(`Unknown protocol: ${this.protocol}`);
            }
        } catch (error) {
            this.connecting = false;
            this.onError(error);
            throw error;
        }
    }

    /**
     * Disconnect from the console
     */
    disconnect() {
        if (this.client) {
            if (this.protocol === 'vnc' && this.client.disconnect) {
                this.client.disconnect();
            } else if (this.protocol === 'spice' && this.client.stop) {
                this.client.stop();
            }
            this.client = null;
        }
        this.connected = false;
        this.connecting = false;
    }

    /**
     * Switch to a different protocol
     */
    async switchProtocol(newProtocol) {
        if (newProtocol === this.protocol) {
            return;
        }

        this.disconnect();
        this.protocol = newProtocol;

        // Clear the container
        this.container.innerHTML = '';

        await this.connect();
    }

    /**
     * Send Ctrl+Alt+Del to the VM
     */
    sendCtrlAltDel() {
        if (!this.connected || !this.client) {
            console.warn('Not connected');
            return;
        }

        if (this.protocol === 'vnc') {
            this.client.sendCtrlAltDel();
        } else if (this.protocol === 'spice') {
            // SPICE uses different method
            if (this.client.sendCtrlAltDel) {
                this.client.sendCtrlAltDel();
            }
        }
    }

    /**
     * Send a key combination (VNC only)
     */
    sendKey(keysym, down) {
        if (!this.connected || !this.client || this.protocol !== 'vnc') {
            return;
        }
        this.client.sendKey(keysym, null, down);
    }

    /**
     * Set view-only mode (VNC only)
     */
    setViewOnly(viewOnly) {
        if (this.protocol === 'vnc' && this.client) {
            this.client.viewOnly = viewOnly;
        }
    }

    /**
     * Set scaling mode (VNC only)
     */
    setScaleViewport(scale) {
        if (this.protocol === 'vnc' && this.client) {
            this.client.scaleViewport = scale;
        }
    }

    /**
     * Request fullscreen
     */
    requestFullscreen() {
        if (this.container.requestFullscreen) {
            this.container.requestFullscreen();
        } else if (this.container.webkitRequestFullscreen) {
            this.container.webkitRequestFullscreen();
        } else if (this.container.mozRequestFullScreen) {
            this.container.mozRequestFullScreen();
        }
    }

    /**
     * Exit fullscreen
     */
    exitFullscreen() {
        if (document.exitFullscreen) {
            document.exitFullscreen();
        } else if (document.webkitExitFullscreen) {
            document.webkitExitFullscreen();
        } else if (document.mozCancelFullScreen) {
            document.mozCancelFullScreen();
        }
    }

    /**
     * Toggle fullscreen
     */
    toggleFullscreen() {
        if (document.fullscreenElement || document.webkitFullscreenElement) {
            this.exitFullscreen();
        } else {
            this.requestFullscreen();
        }
    }

    /**
     * Get current connection status
     */
    getStatus() {
        return {
            connected: this.connected,
            connecting: this.connecting,
            protocol: this.protocol,
            sessionId: this.sessionId
        };
    }

    // ========================================================================
    // Private Methods
    // ========================================================================

    async _fetch(url, options = {}) {
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        const response = await fetch(this.apiBaseUrl + url, {
            ...options,
            headers
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({ detail: response.statusText }));
            throw new Error(error.detail || 'API request failed');
        }

        return response.json();
    }

    async _connectVNC() {
        // Get VNC ticket from API
        const ticketData = await this._fetch(`/api/session/${this.sessionId}/vnc-ticket`, {
            method: 'POST'
        });

        console.log('VNC ticket received, connecting to:', ticketData.websocket_url);

        // Check if RFB (noVNC) is available
        if (typeof RFB === 'undefined') {
            throw new Error('noVNC library not loaded. Please include noVNC/core/rfb.js');
        }

        // Create noVNC client
        this.client = new RFB(this.container, ticketData.websocket_url, {
            credentials: { password: ticketData.ticket },
            ...this.vncOptions
        });

        // Set up event listeners
        this.client.addEventListener('connect', () => {
            console.log('VNC connected');
            this.connected = true;
            this.connecting = false;
            this.onConnect({ protocol: 'vnc' });
        });

        this.client.addEventListener('disconnect', (e) => {
            console.log('VNC disconnected:', e.detail);
            this.connected = false;
            this.connecting = false;
            this.onDisconnect({
                protocol: 'vnc',
                clean: e.detail.clean,
                reason: e.detail.reason
            });
        });

        this.client.addEventListener('credentialsrequired', () => {
            console.log('VNC credentials required');
            this.onCredentialsRequired({ protocol: 'vnc' });
        });

        this.client.addEventListener('securityfailure', (e) => {
            console.error('VNC security failure:', e.detail);
            this.onError(new Error(`Security failure: ${e.detail.reason}`));
        });

        this.client.addEventListener('clipboard', (e) => {
            this.onClipboard({ protocol: 'vnc', text: e.detail.text });
        });

        this.client.addEventListener('desktopname', (e) => {
            console.log('VNC desktop name:', e.detail.name);
        });

        // Apply options
        this.client.scaleViewport = this.vncOptions.scaleViewport;
        this.client.resizeSession = this.vncOptions.resizeSession;
        this.client.clipViewport = this.vncOptions.clipViewport;
        this.client.dragViewport = this.vncOptions.dragViewport;
        this.client.showDotCursor = this.vncOptions.showDotCursor;
    }

    async _connectSPICE() {
        // Get SPICE ticket from API
        const ticketData = await this._fetch(`/api/session/${this.sessionId}/spice-ticket`, {
            method: 'POST'
        });

        console.log('SPICE ticket received, connecting to:', ticketData.websocket_url);

        // Check if SpiceMainConn is available
        if (typeof SpiceMainConn === 'undefined') {
            throw new Error('spice-html5 library not loaded. Please include spice-html5 scripts');
        }

        // Create a canvas element for SPICE display
        const canvas = document.createElement('canvas');
        canvas.id = `spice-canvas-${this.sessionId}`;
        canvas.className = 'spice-display';
        this.container.appendChild(canvas);

        // Create SPICE connection
        this.client = new SpiceMainConn({
            uri: ticketData.websocket_url,
            password: ticketData.password,
            screen_id: canvas.id,
            onerror: (e) => {
                console.error('SPICE error:', e);
                this.connected = false;
                this.connecting = false;
                this.onError(new Error(e.message || 'SPICE connection error'));
            },
            onsuccess: () => {
                console.log('SPICE connected');
                this.connected = true;
                this.connecting = false;
                this.onConnect({ protocol: 'spice' });
            },
            onagent: this.spiceOptions.enableClipboard ? (agent) => {
                console.log('SPICE agent connected');
            } : undefined
        });
    }
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = LabConsoleClient;
}

// Also attach to window for script tag usage
if (typeof window !== 'undefined') {
    window.LabConsoleClient = LabConsoleClient;
}
