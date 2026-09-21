import axios from 'axios';

// FastAPI Backend ka address
const API = axios.create({
    baseURL: 'http://localhost:8000/api/scan',
});

// =====================================================================
// 1. URL Scan (Existing - Preserved)
// =====================================================================
export const scanUrl = async (url) => {
    try {
        const response = await API.post('/check-url', { url: url });
        return response.data;
    } catch (error) {
        console.error("URL Scan API Error:", error);
        throw error;
    }
};

// =====================================================================
// 2. IP Address Scan (NEW)
// =====================================================================
export const scanIp = async (ip) => {
    try {
        const response = await API.post('/check-ip', { ip: ip });
        return response.data;
    } catch (error) {
        console.error("IP Scan API Error:", error);
        throw error;
    }
};

// =====================================================================
// 3. File Hash / APK Hash Scan (NEW)
// =====================================================================
export const scanHash = async (hash, scanType = 'file') => {
    try {
        const response = await API.post('/check-hash', { hash: hash, scan_type: scanType });
        return response.data;
    } catch (error) {
        console.error("Hash Scan API Error:", error);
        throw error;
    }
};

// =====================================================================
// 4. History (Existing - Preserved)
// =====================================================================
export const getHistory = async () => {
    try {
        const response = await API.get('/history');
        return response.data;
    } catch (error) {
        console.error("History fetch error:", error);
        return [];
    }
};