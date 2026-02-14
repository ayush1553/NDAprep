/**
 * DB.JS - API Based Performance Data
 * Communicates with the Node.js server.
 */

const DB_CONFIG = {
    API_URL: '/api'
};

const DB = {
    // --- ATTEMPTS TABLE ---
    async saveAttempt(attemptData) {
        const response = await fetch(`${DB_CONFIG.API_URL}/attempts`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(attemptData)
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || 'Failed to save attempt to server');
        }
        return await response.json();
    },

    async getAttemptsByUser(userId) {
        const response = await fetch(`${DB_CONFIG.API_URL}/attempts/user/${userId}`);
        if (!response.ok) return [];
        return await response.json();
    },

    async getAttemptById(attemptId) {
        const response = await fetch(`${DB_CONFIG.API_URL}/attempts/id/${attemptId}`);
        if (!response.ok) return null;
        return await response.json();
    },

    // --- SUMMARY CALCULATIONS (Move some to client for speed if needed, but fetching data first) ---
    async getPerformanceSummary(userId) {
        const attempts = await this.getAttemptsByUser(userId);
        if (attempts.length === 0) return null;

        const total = attempts.length;
        const pyqs = attempts.filter(a => a.test_type === 'PYQ').length;
        const mocks = attempts.filter(a => a.test_type === 'Mock').length;

        const sumScore = attempts.reduce((acc, a) => acc + parseFloat(a.score), 0);
        const sumAccuracy = attempts.reduce((acc, a) => acc + parseFloat(a.accuracy), 0);

        return {
            totalTests: total,
            pyqCount: pyqs,
            mockCount: mocks,
            avgScore: (sumScore / total).toFixed(1),
            avgAccuracy: (sumAccuracy / total).toFixed(1)
        };
    },

    async getSubjectSummary(userId, subject) {
        const allAttempts = await this.getAttemptsByUser(userId);
        const attempts = allAttempts.filter(a => a.subject === subject);
        if (attempts.length === 0) return null;

        const sumAccuracy = attempts.reduce((acc, a) => acc + parseFloat(a.accuracy), 0);
        return {
            count: attempts.length,
            avgAccuracy: (sumAccuracy / attempts.length).toFixed(1)
        };
    }
};

window.DB = DB;
