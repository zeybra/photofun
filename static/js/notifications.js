// Push notification functionality
class NotificationManager {
    constructor() {
        this.isSupported = 'serviceWorker' in navigator && 'PushManager' in window;
        this.vapidPublicKey = null;
    }

    async init() {
        if (!this.isSupported) {
            console.log('Push notifications not supported');
            return false;
        }

        try {
            // Register service worker
            const registration = await navigator.serviceWorker.register('/static/sw.js');
            console.log('Service Worker registered');

            // Get VAPID public key from server
            const response = await fetch('/api/vapid-public-key');
            const data = await response.json();
            this.vapidPublicKey = data.publicKey;

            return true;
        } catch (error) {
            console.error('Service Worker registration failed:', error);
            return false;
        }
    }

    async requestPermission() {
        if (!this.isSupported) return false;

        const permission = await Notification.requestPermission();
        return permission === 'granted';
    }

    async subscribe() {
        if (!this.isSupported || !this.vapidPublicKey) return null;

        try {
            const registration = await navigator.serviceWorker.ready;
            const subscription = await registration.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: this.urlBase64ToUint8Array(this.vapidPublicKey)
            });

            // Send subscription to server
            await fetch('/api/subscribe', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('[name=csrf_token]').value
                },
                body: JSON.stringify(subscription)
            });

            return subscription;
        } catch (error) {
            console.error('Subscription failed:', error);
            return null;
        }
    }

    urlBase64ToUint8Array(base64String) {
        const padding = '='.repeat((4 - base64String.length % 4) % 4);
        const base64 = (base64String + padding)
            .replace(/\-/g, '+')
            .replace(/_/g, '/');

        const rawData = window.atob(base64);
        const outputArray = new Uint8Array(rawData.length);

        for (let i = 0; i < rawData.length; ++i) {
            outputArray[i] = rawData.charCodeAt(i);
        }
        return outputArray;
    }
}

// Initialize notification manager
const notificationManager = new NotificationManager();

// Auto-initialize when page loads
document.addEventListener('DOMContentLoaded', async function() {
    const initialized = await notificationManager.init();

    if (initialized) {
        // Show notification permission request on first visit
        const hasPermission = await notificationManager.requestPermission();
        if (hasPermission) {
            await notificationManager.subscribe();
        }
    }
});

// Function to manually request notifications (can be called from buttons)
window.enableNotifications = async function() {
    const hasPermission = await notificationManager.requestPermission();
    if (hasPermission) {
        const subscription = await notificationManager.subscribe();
        if (subscription) {
            alert('Notifications enabled! You\'ll get updates about new challenges and photos.');
        }
    }
};