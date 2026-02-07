// telegramManager.js
//curl https://api.telegram.org/bot8363987157:AAEun4yptxoXVcOHXky1vYxApahaca65sNc/getUpdates

const TelegramBot = require('node-telegram-bot-api');

const zoneBots = {
    "Tangail-Bot": {
        token: "8363987157:AAEun4yptxoXVcOHXky1vYxApahaca65sNc",
        chatId: "5381273194",
        ips: ["10.11.120.4", "10.11.120.8", "172.31.104.3", "10.11.120.5", "10.11.120.7", "10.11.120.9", "10.11.120.12", "10.11.120.10","172.31.104.2"]
    },
    "Kolkata-Bot": {
        token: "8261074525:AAEWxbds4JTGd-k5cHZT85QueA2LFuTz06s",
        chatId: "5381273194",
        ips: ["172.31.101.2","172.31.252.45","172.31.252.25", "172.31.101.106"]
    },
    "Benapole-Bot": {
        token: "8394735227:AAE3wjz4C0h8ESyweIRnyyUi8SOAiOTFxN8",
        chatId: "5381273194",
        ips: ["172.31.101.82","172.31.101.78","172.31.252.12", "172.31.101.30"]
    },
};

const allowedPrefixes = ["ae", "et", "lt", "xe", "10GE", "20GE", "30GE", "40GE", "25GE", "100GE", "Ethernet","GigaEthernet","TGigaEthernet"];

const bots = {};

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
 * Sends a message to the bot responsible for the device's IP, with optional interface filtering.
 * For port alerts, pass the interfaceName to check against allowedPrefixes.
 * Only interfaces whose description starts with an allowed prefix will trigger the alert.
 */
const sendAlert = async (deviceIp, message, interfaceName = null) => {
    console.log(`?? Checking alert for IP: ${deviceIp}, Interface: ${interfaceName || 'None'}`);

    // Filter by Interface Description if provided (for port alerts)
    if (interfaceName) {
        const isAllowed = allowedPrefixes.some(prefix => 
            interfaceName.toLowerCase().startsWith(prefix.toLowerCase())
        );
        if (!isAllowed) {
            console.log(`?? Skipping: Interface '${interfaceName}' does not start with an allowed prefix.`);
            return; // Skip if it doesn't match allowed prefixes
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
                    console.log(`? Alert sent to zone ${zone} for IP ${deviceIp}`);
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
//(async () => {
    //console.log('Testing manual send...');
    //await sendAlert("172.31.252.12", "Manual test alert from bot!");
//})();