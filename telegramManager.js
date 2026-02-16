// telegrammanager.js
const TelegramBot = require('node-telegram-bot-api');
require('dotenv').config(); // Load .env variables

// Define zones with tokens and chat IDs from .env
const zoneBots = {
    "Tangail-Bot": {
        token: process.env.TELEGRAM_BOT_TOKEN_TANGAIL,
        chatId: process.env.TELEGRAM_CHAT_ID_TANGAIL,
        ips: ["10.11.120.4", "10.11.120.8", "172.31.104.3", "10.11.120.5", "10.11.120.7", "10.11.120.9", "10.11.120.12", "10.11.120.10", "172.31.104.2"]
    },
    "Kolkata-Bot": {
        token: process.env.TELEGRAM_BOT_TOKEN_KOLKATA,
        chatId: process.env.TELEGRAM_CHAT_ID_KOLKATA,
        ips: ["172.31.101.2", "172.31.252.45", "172.31.252.25", "172.31.101.106", "172.31.101.114", "172.31.101.115", "172.31.101.122", "172.31.101.123"]
    },
    "Benapole-Bot": {
        token: process.env.TELEGRAM_BOT_TOKEN_BENAPOLE,
        chatId: process.env.TELEGRAM_CHAT_ID_BENAPOLE,
        ips: ["172.31.101.82", "172.31.101.78", "172.31.252.12", "172.31.101.30"]
    },
	"Dhaka-Bot": {
        token: process.env.TELEGRAM_BOT_TOKEN_DHK_DC,
        chatId: process.env.TELEGRAM_CHAT_ID_DHK_DC,
        ips: ["172.31.101.54", "172.31.101.62", "172.31.102.3", "172.31.102.2", "172.31.103.2", "172.31.101.26", "172.31.101.42", "172.23.23.2", "172.31.101.34", "172.31.224.2","172.31.101.66", "172.31.252.7", "172.31.102.7", "172.31.100.28", "172.16.101.70", "172.31.252.1" ]
    },
    "NHK-Bot": {
    token: process.env.TELEGRAM_BOT_TOKEN_NHK,
    chatId: process.env.TELEGRAM_CHAT_ID_NHK,
    ips: [
        "172.16.115.46", "172.31.252.19", "172.22.5.93", "172.16.26.1", 
        "172.16.111.110", "172.22.1.102", "172.16.111.106", "172.22.10.106", 
        "172.16.111.136", "172.16.111.172", "172.16.111.190", "172.16.111.203", 
        "172.16.111.209", "172.16.111.212", "172.16.111.213", "172.16.111.216", 
        "172.16.111.223", "172.16.111.239", "172.16.111.240", "172.16.111.246", 
        "172.16.114.10", "172.16.114.11", "172.16.114.12", "172.16.114.2", 
        "172.16.114.4", "172.16.114.5", "172.16.114.6", "172.16.114.7", 
        "172.16.114.8", "172.16.114.9", "172.16.100.2", "172.16.113.252", 
        "172.16.100.54", "172.16.111.102", "172.16.111.3", "192.168.176.1", 
        "172.31.252.5"
    ]
   },
};

// Regex patterns for allowed prefixes (case-insensitive)
// - "ae": Must be "ae" followed by one or more digits (no dots or sub-interfaces like "ae2.1")
const allowedPrefixesRegex = [
    /^ae\d+$/i,  // e.g., ae1, ae2, ae10 (but not ae2.1)
    /^et/i,      // e.g., et, et1, et2
    /^lt/i,      // e.g., lt, lt1, lt2
    /^xe/i,      // e.g., xe, xe1, xe2
    /^10GE/i,    // e.g., 10GE, 10GE1
    /^20GE/i,    // e.g., 20GE, 20GE1
    /^30GE/i,    // e.g., 30GE, 30GE1
    /^40GE/i,    // e.g., 40GE, 40GE1
    /^25GE/i,    // e.g., 25GE, 25GE1
    /^100GE/i,   // e.g., 100GE, 100GE1
    /^Ethernet/i, // e.g., Ethernet, Ethernet1
    /^GigaEthernet/i, // e.g., GigaEthernet, GigaEthernet1
    /^TGigaEthernet/i, // e.g., TGigaEthernet, TGigaEthernet1
];

const bots = {};

// Initialize bots for each zone
Object.keys(zoneBots).forEach(zone => {
    const config = zoneBots[zone];
    if (config.token) {
        bots[zone] = new TelegramBot(config.token, { polling: false });
        console.log(`? Telegram Bot initialized for zone: ${zone}`);
    } else {
        console.error(`? No token for zone: ${zone}`);
    }
});

/**
 * Checks if an interface name matches any allowed prefix using regex.
 * @param {string} interfaceName - The interface name (e.g., "ae1", "Ethernet2").
 * @returns {boolean} - True if it matches, false otherwise.
 */
const isInterfaceAllowed = (interfaceName) => {
    if (!interfaceName) return false;
    return allowedPrefixesRegex.some(regex => regex.test(interfaceName));
};

/**
 * Sends a port alert message to the bot responsible for the device's IP.
 * Only sends if the interface matches the allowed prefixes.
 * @param {string} deviceIp - The IP address of the device.
 * @param {string} message - The alert message.
 * @param {string} interfaceName - The interface name (e.g., "ae1") for filtering.
 */
const sendAlert = async (deviceIp, message, interfaceName = null) => {
    console.log(`?? Checking alert for IP: ${deviceIp}, Interface: ${interfaceName || 'None'}`);

    // Filter by Interface Name if provided (for port alerts)
    if (interfaceName) {
        if (!isInterfaceAllowed(interfaceName)) {
            console.log(`?? Skipping: Interface '${interfaceName}' does not match allowed prefixes.`);
            return; // Skip if it doesn't match
        }
    }

    // Find the correct bot for this IP
    for (const zone in zoneBots) {
        const config = zoneBots[zone];
        console.log(`Checking zone ${zone} IPs: ${config.ips.join(', ')}`);
        if (config.ips.includes(deviceIp)) {
            const bot = bots[zone];
            if (bot && config.chatId) {
                try {
                    await bot.sendMessage(config.chatId, message);
                    console.log(`?? Alert sent to zone ${zone} for IP ${deviceIp}`);
                    return;
                } catch (err) {
                    console.error(`? Send failed for zone ${zone}:`, err.message);
                    return;
                }
            } else {
                console.error(`? Bot or chatId missing for zone ${zone}`);
            }
        }
    }
    
    console.warn(`?? No zone configured for IP: ${deviceIp}`);
};

module.exports = { sendAlert };
// Temporary test - remove after testing
(async () => {
    //console.log('Testing Message...');
    await sendAlert("10.11.120.8", "Testing Message...!");
})();