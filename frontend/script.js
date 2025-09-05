// Matrix Chat Client
class MatrixChatClient {
    constructor() {
        this.client = null;
        this.currentRoom = null;
        this.isConnected = false;
        
        this.initializeElements();
        this.setupEventListeners();
    }
    
    initializeElements() {
        this.loginSection = document.getElementById('loginSection');
        this.chatSection = document.getElementById('chatSection');
        this.connectionStatus = document.getElementById('connectionStatus');
        this.loginForm = document.getElementById('loginForm');
        this.roomSelect = document.getElementById('roomSelect');
        this.joinRoomBtn = document.getElementById('joinRoomBtn');
        this.messages = document.getElementById('messages');
        this.messageInput = document.getElementById('messageInput');
        this.sendBtn = document.getElementById('sendBtn');
        this.logContent = document.getElementById('logContent');
    }
    
    setupEventListeners() {
        this.loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        this.joinRoomBtn.addEventListener('click', () => this.joinRoom());
        this.sendBtn.addEventListener('click', () => this.sendMessage());
        this.messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.sendMessage();
            }
        });
    }
    
    log(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${type}`;
        logEntry.textContent = `[${timestamp}] ${message}`;
        this.logContent.appendChild(logEntry);
        this.logContent.scrollTop = this.logContent.scrollHeight;
        console.log(`[${type.toUpperCase()}] ${message}`);
    }
    
    async handleLogin(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        if (!username || !password) {
            this.log('Please enter both username and password', 'error');
            return;
        }
        
        try {
            this.log('Attempting to login...', 'info');
            
            // Create Matrix client
            this.client = matrix.createClient({
                baseUrl: "http://localhost:8008",
                useAuthorizationHeader: true
            });
            
            // Login
            const response = await this.client.login('m.login.password', {
                user: username,
                password: password
            });
            
            this.log(`Login successful! User ID: ${response.user_id}`, 'success');
            
            // Update UI
            this.isConnected = true;
            this.connectionStatus.textContent = 'Connected';
            this.connectionStatus.className = 'connection-status connected';
            this.loginSection.style.display = 'none';
            this.chatSection.style.display = 'block';
            
            // Load rooms
            await this.loadRooms();
            
            // Start sync
            this.client.startClient();
            this.setupEventHandlers();
            
        } catch (error) {
            this.log(`Login failed: ${error.message}`, 'error');
        }
    }
    
    async loadRooms() {
        try {
            const rooms = this.client.getRooms();
            this.roomSelect.innerHTML = '<option value="">Select a room...</option>';
            
            rooms.forEach(room => {
                const option = document.createElement('option');
                option.value = room.roomId;
                option.textContent = room.name || room.roomId;
                this.roomSelect.appendChild(option);
            });
            
            this.roomSelect.addEventListener('change', () => {
                this.joinRoomBtn.disabled = !this.roomSelect.value;
            });
            
            this.log(`Loaded ${rooms.length} rooms`, 'info');
        } catch (error) {
            this.log(`Failed to load rooms: ${error.message}`, 'error');
        }
    }
    
    async joinRoom() {
        const roomId = this.roomSelect.value;
        if (!roomId) return;
        
        try {
            this.log(`Joining room: ${roomId}`, 'info');
            
            // Join the room
            await this.client.joinRoom(roomId);
            
            this.currentRoom = this.client.getRoom(roomId);
            this.messageInput.disabled = false;
            this.sendBtn.disabled = false;
            
            // Load recent messages
            this.loadMessages();
            
            this.log(`Successfully joined room: ${roomId}`, 'success');
        } catch (error) {
            this.log(`Failed to join room: ${error.message}`, 'error');
        }
    }
    
    loadMessages() {
        if (!this.currentRoom) return;
        
        this.messages.innerHTML = '';
        const events = this.currentRoom.timeline;
        
        events.forEach(event => {
            if (event.getType() === 'm.room.message') {
                this.displayMessage(event);
            }
        });
    }
    
    displayMessage(event) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message';
        
        const content = event.getContent();
        const sender = event.getSender();
        const isOwn = sender === this.client.getUserId();
        
        if (isOwn) {
            messageDiv.classList.add('own');
        } else {
            messageDiv.classList.add('other');
        }
        
        const header = document.createElement('div');
        header.className = 'message-header';
        header.textContent = `${sender} - ${new Date(event.getTs()).toLocaleTimeString()}`;
        
        const messageContent = document.createElement('div');
        messageContent.className = 'message-content';
        messageContent.textContent = content.body || '';
        
        messageDiv.appendChild(header);
        messageDiv.appendChild(messageContent);
        this.messages.appendChild(messageDiv);
        
        // Scroll to bottom
        this.messages.scrollTop = this.messages.scrollHeight;
    }
    
    async sendMessage() {
        const message = this.messageInput.value.trim();
        if (!message || !this.currentRoom) return;
        
        try {
            await this.client.sendTextMessage(this.currentRoom.roomId, message);
            this.messageInput.value = '';
            this.log(`Message sent: ${message}`, 'info');
        } catch (error) {
            this.log(`Failed to send message: ${error.message}`, 'error');
        }
    }
    
    setupEventHandlers() {
        // Handle new messages
        this.client.on('Room.timeline', (event, room) => {
            if (event.getType() === 'm.room.message' && room === this.currentRoom) {
                this.displayMessage(event);
            }
        });
        
        // Handle connection status
        this.client.on('sync', (state) => {
            if (state === 'SYNCING') {
                this.log('Syncing with server...', 'info');
            } else if (state === 'PREPARED') {
                this.log('Sync complete', 'success');
            }
        });
        
        // Handle errors
        this.client.on('error', (error) => {
            this.log(`Client error: ${error.message}`, 'error');
        });
    }
}

// Initialize the chat client when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new MatrixChatClient();
});
