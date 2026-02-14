// Analysis Screen Logic

let testResult = null;
let questionsData = [];

document.addEventListener('DOMContentLoaded', async () => {
    try {
        testResult = JSON.parse(localStorage.getItem('ndaExamResult'));

        if (!testResult) {
            alert("No test results found!");
            window.location.href = 'index.html';
            return;
        }

        // Set Header Title
        if (document.getElementById('header-title-text')) {
            let title = "UPSC NDA Analysis";
            if (testResult.test_type === 'ChapterTest') {
                title = testResult.subject + " : CT " + (testResult.test_id.replace('ct_ct', '').replace('_', ' '));
            } else if (testResult.test_type === 'Mock') {
                title = "UPSC NDA Mock: " + (testResult.test_id.replace('mock_', ''));
            } else {
                // PYQ
                const year = testResult.year || "202x";
                const session = testResult.session || "1";
                title = `UPSC NDA ${session}/${year} PYQ`;
            }
            document.getElementById('header-title-text').textContent = title;
        }

        // Load Questions Data - Wait but don't crash if fails
        try {
            await loadQuestions();
        } catch (e) {
            console.error("Questions load error:", e);
        }

        // Populate UI immediately - Critical Step
        try {
            populateAnalysis();
            renderSolutions('all');
        } catch (e) {
            alert("Error displaying analysis metrics: " + e.message);
            console.error(e);
        }

        // Load Topic Classification
        await loadClassification();

    } catch (criticalError) {
        alert("Critical Error in Analysis Page: " + criticalError.message);
        console.error(criticalError);
    }
});

async function loadQuestions() {
    return new Promise((resolve) => {
        const type = testResult.test_type || 'PYQ';
        const subj = testResult.subject || 'Mathematics';
        const yr = testResult.year || '2022';
        const sess = testResult.session || '2';

        let src = '';

        if (type === 'ChapterTest') {
            // extract slug from test_id: "ct_slug" -> "slug"
            const slug = testResult.test_id.replace(/^ct_/, '');

            if (subj === 'Mathematics') {
                src = `data/chapter_test_mat/${slug}.js`;
            } else {
                // GAT Logic: Subject -> Subfolder
                // e.g. "Physics" -> "physics", "Work, Energy & Power" -> "work_energy_and_power" (if that was subject, but subject is Physics)
                // detailed subject mapping might be needed if subject is generic "GAT". 
                // Usually testResult.subject is "Physics", "Chemistry", etc. for GAT CTs?
                // Let's assume testResult.subject is the specific subject like "Physics".

                const subfolder = subj.toLowerCase().replace(/ & /g, '_and_').replace(/ /g, '_');
                src = `data/chapter_test_gat/${subfolder}/${slug}.js`;
            }

        } else if (type === 'Mock') {
            const slug = testResult.test_id.replace(/^mock_/, '');
            // Mock folder logic? 
            // exam.html says: const folder = subj === 'Mathematics' ? 'mock_test_mat' : 'mock_test_gat';
            // If testResult.subject is 'GAT' or 'General Ability Test', use gat folder.

            let folder = 'mock_test_mat'; // default
            if (subj.includes('General') || subj.includes('GAT')) {
                folder = 'mock_test_gat';
            }
            src = `data/${folder}/${slug}.js`;

        } else {
            // PYQ
            src = `data/questions/${subj}_${yr}_${sess}.js`;
        }

        console.log("Loading questions from:", src);

        const script = document.createElement('script');
        script.src = src;
        script.onload = () => {
            questionsData = window.questionsData || [];
            console.log("Questions Loaded. Count:", questionsData.length);
            resolve();
        };
        script.onerror = () => {
            console.error("Failed to load questions data from", src);
            resolve();
        };
        document.head.appendChild(script);
    });
}

function populateAnalysis() {
    // Metrics
    document.getElementById('val-score').textContent = (testResult.score || 0);
    // Score Total (Denominator)
    let maxScore = parseFloat(testResult.max_score || 0);

    // PATCH: Fix legacy data where GAT Chapter Tests were saved with 25 marks instead of 40
    if (testResult.test_type === 'ChapterTest' && (testResult.subject !== 'Mathematics')) {
        // Recalculate based on question count: GAT = 4 marks per question
        const qCount = testResult.total_questions || testResult.detailedResults?.length || 10;
        maxScore = qCount * 4;
    }

    document.getElementById('val-total-score').textContent = '/' + maxScore;

    document.getElementById('val-accuracy').textContent = testResult.accuracy || 0;

    // Attempted
    document.getElementById('val-attempted').textContent = testResult.attempted || 0;
    document.getElementById('val-total-questions').textContent = '/' + (testResult.total_questions || 0);

    // Summary Sub-values
    document.getElementById('count-correct').textContent = testResult.correct || 0;
    document.getElementById('count-incorrect').textContent = testResult.incorrect || 0;
    document.getElementById('count-unattempted').textContent = testResult.unattempted || 0;

    // Derived/Mocked Stats - HIDDEN in new design but logic kept safe
    // const totalUsers = 4230; 
    // const rank = Math.floor(Math.random() * 500) + 10;
}

// Reattempt Logic: Redirect to instructions with same parameters
function reattemptTest() {
    if (!testResult) return;

    // Reconstruct URL parameters
    const params = new URLSearchParams();

    if (testResult.test_type === 'ChapterTest') {
        params.append('type', 'ChapterTest');
        // Extract chapter slug from test_id (e.g., ct_ct01_...)
        // testResult.test_id stores "ct_ct...". 
        // We know urlParams.get('chapter') was widely used.
        // Let's use the stored subject and reconstruct chapter slug if possible, 
        // or just use generic if data is missing. 
        // Better approach: Rely on stored 'test_id' which is 'ct_{slug}'
        const slug = testResult.test_id.replace('ct_', '');
        params.append('subject', testResult.subject);
        params.append('chapter', slug);

    } else if (testResult.test_type === 'Mock') {
        params.append('type', 'Mock');
        // test_id is "mock_{slug}"
        const slug = testResult.test_id.replace('mock_', '');
        params.append('slug', slug);

    } else {
        // Standard PYQ
        params.append('year', testResult.year || '2022');
        params.append('session', testResult.session || '2');
        params.append('subject', testResult.subject || 'Mathematics');
    }

    window.location.href = `instructions.html?${params.toString()}`;
}

function renderSolutions(filter = 'all') {
    const container = document.getElementById('solutions-container');
    container.innerHTML = '';

    if (!questionsData || !testResult.detailedResults) return;

    const filtered = questionsData.filter((q, i) => {
        const res = testResult.detailedResults[i];
        if (filter === 'all') return true;
        if (filter === 'incorrect') return res.userAnswer && !res.isCorrect;
        if (filter === 'unattempted') return !res.userAnswer;
        return true;
    });

    const chipAll = document.getElementById('chip-all');
    if (chipAll) chipAll.textContent = questionsData.length;

    // Update counts for other pills if elements exist
    const incorrectCount = questionsData.filter((q, i) => {
        const res = testResult.detailedResults[i];
        return res.userAnswer && !res.isCorrect;
    }).length;
    const unattemptedCount = questionsData.filter((q, i) => {
        const res = testResult.detailedResults[i];
        return !res.userAnswer;
    }).length;

    const chipIncorrect = document.getElementById('chip-incorrect');
    if (chipIncorrect) chipIncorrect.textContent = incorrectCount;

    const chipUnattempted = document.getElementById('chip-unattempted');
    if (chipUnattempted) chipUnattempted.textContent = unattemptedCount;


    document.getElementById('sol-total-count').textContent = `${filtered.length} Questions`;

    filtered.forEach((q, i) => {
        const actualIndex = questionsData.indexOf(q);
        const res = testResult.detailedResults[actualIndex];

        let statusClass = 'unattempted';
        if (res.userAnswer) {
            statusClass = res.isCorrect ? 'correct' : 'incorrect';
        }

        const card = document.createElement('div');
        card.className = 'solution-card';
        card.innerHTML = `
            <div class="card-header">
                <div class="question-meta">
                    <div class="question-number ${statusClass}">${actualIndex + 1}</div>
                    ${res.timeSpent ? `<div class="time-badge"><i class="fa-regular fa-clock"></i> ${formatTime(res.timeSpent)}</div>` : ''}
                </div>
                <i class="fa-regular fa-bookmark bookmark"></i>
            </div>
            <div class="question-text">${q.text}</div>
        `;

        container.appendChild(card);
    });
}

function switchTab(tab) {
    document.querySelectorAll('.tab-item').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

    // Find button by onclick attribute to be safe
    const activeBtn = Array.from(document.querySelectorAll('.tab-item')).find(b => b.getAttribute('onclick') && b.getAttribute('onclick').includes(tab));
    if (activeBtn) activeBtn.classList.add('active');

    const activeContent = document.getElementById(`tab-${tab}`);
    if (activeContent) activeContent.classList.add('active');
}

function filterSolutions(type) {
    document.querySelectorAll('.pill').forEach(c => c.classList.remove('active'));
    // Find the pill that was clicked or matches the type
    // We can't easily find "this" without passing it. 
    // Instead, look for the pill containing the text or id

    // Better way: Logic to highlight based on type
    // All pills have onclick="filterSolutions('type')"

    const activePill = Array.from(document.querySelectorAll('.pill')).find(p => p.getAttribute('onclick') && p.getAttribute('onclick').includes(`'${type}'`));
    if (activePill) activePill.classList.add('active');

    renderSolutions(type);
}

// --- TOPIC ANALYSIS LOGIC ---

let topicStats = []; // Stores processed stats

async function loadClassification() {
    // Determine file based on test info
    // Logic: Look for data/questions/questions_classification/{Subject}_{Year}_{Session}_classification.js
    // MOCK MODE: If mock, we might need a specific map or default to GAT if it's GAT.

    let filename = "";

    if (testResult.test_type === 'ChapterTest') {
        return; // No topic analysis for chapter tests yet
    }

    // PYQ Structure: Subject_Year_Session
    // Example: GAT_2020_2
    const subject = testResult.subject || "Mathematics";
    const year = testResult.year || "2022";
    const session = testResult.session || "2";

    // Hack for the specific user request: "GAT 2020 2"
    // User file: GAT_2020_2_classification.js
    // We try to construct this.

    const baseName = `${subject}_${year}_${session}`;
    filename = `data/questions/questions_classification/${baseName}_classification.js`;

    // Dynamic Load
    return new Promise((resolve) => {
        const script = document.createElement('script');
        script.src = filename;
        script.onload = () => {
            console.log("Classification loaded successfully:", filename);
            if (window.topicClassification) {
                processTopicAnalytics();
            } else {
                console.error("Classification Loaded but window.topicClassification is undefined!");
            }
            resolve();
        };
        script.onerror = () => {
            console.warn("FAILED to load classification file:", filename);

            // DEBUG: Show error in UI
            const secStr = document.getElementById('list-weak');
            if (secStr) {
                document.getElementById('section-strengths').style.display = 'block';
                secStr.innerHTML = `<div class="empty-state" style="color:red; text-align:left;">
                    Debug Error: Could not load analysis file.<br>
                    Attempted Path: <b>${filename}</b><br>
                    Subject: ${subject}, Year: ${year}, Session: ${session}
                </div>`;
                secStr.classList.add('active'); // Ensure it's visible
            }
            resolve();
        };
        document.head.appendChild(script);
    });
}

function processTopicAnalytics() {
    if (!window.topicClassification || !window.topicClassification[0]) return;

    const mapping = window.topicClassification[0]; // The object inside array
    const detailedRes = testResult.detailedResults || [];

    // Helper Map: Question ID -> Result Status
    // status: 'correct', 'incorrect', 'unattempted' (derived from isCorrect and userAnswer)
    const qMap = {};
    detailedRes.forEach((r, idx) => {
        // ID in classification vs ID in result
        // Result stores 'id' from questions.js. Classification array has IDs.
        // Important: Classification IDs must match the Question IDs.
        // Assuming they do (1-based index or explicit ID).

        let status = 'unattempted';

        // Prioritize explicit status from exam if available
        if (r.status === 'marked') {
            status = 'marked';
        } else if (r.userAnswer) {
            status = r.isCorrect ? 'correct' : 'incorrect';
        }

        qMap[r.id] = status;
    });

    topicStats = [];

    // Iterate Subjects
    for (const [subjectName, topicsObj] of Object.entries(mapping)) {
        // TopicsObj is { "Topic Name": [id1, id2...], ... }

        for (const [topicName, qIds] of Object.entries(topicsObj)) {
            let total = 0;
            let correct = 0;
            let incorrect = 0;
            let attempted = 0;

            let qDetails = [];
            qIds.forEach(qid => {
                // If question exists in this test result
                if (qMap[qid] !== undefined) {
                    total++;
                    const s = qMap[qid];
                    if (s === 'correct') correct++;
                    if (s === 'incorrect') incorrect++;
                    if (s !== 'unattempted') attempted++;

                    qDetails.push({ id: qid, status: s });
                }
            });

            if (total > 0) {
                const percentage = (correct / total) * 100;
                let statusLabel = 'Weak';
                if (percentage >= 70) statusLabel = 'Strong';
                else if (percentage >= 40) statusLabel = 'Average';

                // Specific case: 0 attempts
                if (attempted === 0) statusLabel = 'Not Attempted';

                topicStats.push({
                    subject: subjectName,
                    topic: topicName,
                    total,
                    correct,
                    incorrect,
                    attempted,
                    percentage,
                    statusLabel,
                    qDetails // Added details
                });
            }
        }
    }

    renderTopicUI();
}

function renderTopicUI() {
    renderStrengthsWeaknesses();
    renderDetailedAccordion();
}

function renderStrengthsWeaknesses() {
    const listWeak = document.getElementById('list-weak');
    const listStrong = document.getElementById('list-strong');

    // Sort: Weak (Low %) first, Strong (High %) first
    // Filter out "Not Attempted" from Weak? Or keep? Usually Weak implies attempted but failed.
    // User req: "Weak Topics (sorted by lowest % first)"

    const weakTopics = topicStats.filter(t => t.percentage < 40 && t.statusLabel !== 'Not Attempted').sort((a, b) => a.percentage - b.percentage);
    const strongTopics = topicStats.filter(t => t.percentage >= 70).sort((a, b) => b.percentage - a.percentage);

    listWeak.innerHTML = weakTopics.length ? weakTopics.map(t => createSWCard(t, 'weak')).join('') : '<div class="empty-state">No weak topics found.</div>';
    listStrong.innerHTML = strongTopics.length ? strongTopics.map(t => createSWCard(t, 'strong')).join('') : '<div class="empty-state">No strong topics found. Keep practicing!</div>';
}

function createSWCard(t, type) {
    return `
        <div class="sw-card ${type}">
            <div class="sw-card-header">
                <span>${t.topic}</span>
                <span>${Math.round(t.percentage)}%</span>
            </div>
            <div class="sw-stat-row">
                <span>${t.subject}</span>
                <span>${t.correct}/${t.total} Correct</span>
            </div>
        </div>
    `;
}

function renderDetailedAccordion() {
    const container = document.getElementById('topic-accordion-container');

    // Group by Subject
    const bySubject = {};
    topicStats.forEach(t => {
        if (!bySubject[t.subject]) bySubject[t.subject] = [];
        bySubject[t.subject].push(t);
    });

    let html = '';
    for (const [subj, topics] of Object.entries(bySubject)) {
        // const avgSubj = topics.reduce((acc, t) => acc + t.percentage, 0) / topics.length;

        html += `
            <div class="topic-subject-block">
                <div class="accordion-header" onclick="toggleAccordion(this)">
                    <span class="accordion-title">${subj}</span>
                    <span class="accordion-icon">▼</span>
                </div>
                <div class="accordion-body">
                    ${topics.map(t => `
                        <div class="topic-item">
                            <div class="topic-name">
                                <span>${t.topic}</span>
                            </div>
                            
                            <div class="topic-stats-row">
                                <span class="stat-label">Correct %</span>
                                <div class="topic-progress-track">
                                    <div class="topic-progress-fill ${t.statusLabel.toLowerCase().replace(' ', '-')}" 
                                         style="width: ${t.percentage}%"></div>
                                </div>
                                <span class="stat-val">${Math.round(t.percentage)}%</span>
                            </div>

                            <div class="topic-q-row">
                                <span class="q-label">Q No.</span>
                                <div class="q-bubbles">
                                    ${t.qDetails.map(q => `<div class="q-circle ${q.status}">${q.id}</div>`).join('')}
                                </div>
                            </div>

                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }
    container.innerHTML = html;
}

// UI Helpers
function toggleSW(type) {
    document.querySelectorAll('.sw-toggle').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.sw-list').forEach(l => l.classList.remove('active'));

    const btn = document.querySelector(`.sw-toggle[onclick="toggleSW('${type}')"]`);
    if (btn) btn.classList.add('active');

    document.getElementById(`list-${type}`).classList.add('active');
}

function toggleAccordion(header) {
    header.parentElement.classList.toggle('active');
}

// --- COMPARE SECTION LOGIC ---
let compareHistory = [];
let compareCurrent = null;
let comparePrevious = null;

async function initComparison() {
    if (!testResult || !window.DB || !window.Auth) return;

    const user = Auth.getSession();
    if (!user) {
        document.getElementById('compare-bars-area').innerHTML = '<div class="empty-state">Please login to compare history.</div>';
        return;
    }

    try {
        const allAttempts = await DB.getAttemptsByUser(user.id);

        // Filter by same test
        // Validation: Ensure test_id matches
        const sameTestAttempts = allAttempts.filter(a => a.test_id === testResult.test_id);

        // Sort by date (Newest first)
        sameTestAttempts.sort((a, b) => new Date(b.submitted_at) - new Date(a.submitted_at));

        // Identify "You" (Current) and "Previous"
        // Current is already testResult. Ensure we don't pick it again as "Previous" if it's already in DB.
        compareCurrent = testResult;

        // Find previous: First attempt in history strictly older than current, or just the next one if current is top
        // If current is newly finished, it might be in DB.
        comparePrevious = sameTestAttempts.find(a =>
            a.id !== compareCurrent.id && new Date(a.submitted_at) < new Date(compareCurrent.submitted_at || Date.now())
        );

        // Fallback: If no ID match (legacy), just take the 2nd item if 1st is close to now
        if (!comparePrevious && sameTestAttempts.length > 1) {
            // If the top one is roughly same time as main result, grab next
            comparePrevious = sameTestAttempts[1];
        }

        renderCompareChart('score'); // Default metric

    } catch (err) {
        console.error("Comparison Error:", err);
        document.getElementById('compare-bars-area').innerHTML = '<div class="empty-state">Could not load history.</div>';
    }
}

function switchCompareMetric(metric) {
    // UI Active State
    document.querySelectorAll('.comp-toggle').forEach(b => b.classList.remove('active'));
    document.querySelector(`.comp-toggle[data-metric="${metric}"]`).classList.add('active');

    renderCompareChart(metric);
}

function renderCompareChart(metric) {
    const container = document.getElementById('compare-bars-area');
    const chartContainer = document.querySelector('.compare-chart-container');
    const yAxis = document.querySelector('.chart-y-axis');

    // Set Theme Class
    chartContainer.className = `compare-chart-container theme-${metric}`;

    // Get Data Values
    const valYou = getMetricValue(compareCurrent, metric);
    const valPrev = comparePrevious ? getMetricValue(comparePrevious, metric) : 0;

    // Determine Max for Scale (with buffer)
    let max = Math.max(valYou, valPrev);
    if (metric === 'accuracy' || metric === 'percentage') max = 100;
    else max = max > 0 ? (max * 1.2) : 10; // 20% buffer

    // Generate Y-Axis Labels
    yAxis.innerHTML = `
        <span>${Math.round(max)}</span>
        <span>${Math.round(max / 2)}</span>
        <span>0</span>
    `;

    // Render Bars
    // Logic: Height % = (value / max) * 100
    const hYou = max > 0 ? (valYou / max) * 100 : 0;
    const hPrev = max > 0 ? (valPrev / max) * 100 : 0;

    let html = `
        <!-- YOU BAR -->
        <div class="bar-group">
            <span class="bar-value">${formatMetricDisplay(valYou, metric)}</span>
            <div class="bar-fill bar-you" style="height: ${hYou}%;"></div>
            <span class="bar-label">You</span>
        </div>
    `;

    if (comparePrevious) {
        html += `
            <!-- PREVIOUS BAR -->
            <div class="bar-group">
                <span class="bar-value">${formatMetricDisplay(valPrev, metric)}</span>
                <div class="bar-fill bar-prev" style="height: ${hPrev}%;"></div>
                <span class="bar-label">Previous</span>
            </div>
        `;
    } else {
        // Center "You" if alone? Or just let justify-evenly handle it.
        // justify-evenly handles it fine.
    }

    container.innerHTML = html;
}

function getMetricValue(data, metric) {
    if (!data) return 0;
    switch (metric) {
        case 'score': return parseFloat(data.score || 0);
        case 'accuracy': return parseFloat(data.accuracy || 0);
        case 'attempted': return parseInt(data.attempted || 0);
        case 'correct': return parseInt(data.correct || 0);
        case 'incorrect': return parseInt(data.incorrect || 0);
        case 'time': return parseFloat(data.timeSpent || data.time_taken || 0) / 60; // Minutes
        default: return 0;
    }
}

function formatMetricDisplay(val, metric) {
    if (metric === 'accuracy') return Math.round(val) + '%';
    if (metric === 'time') return Math.round(val) + 'm';
    return Math.round(val);
}

// Call init calls inside the existing DOMContentLoaded, 
// so we need to ensure this function is globally available or explicitly called there.
// Since we can't edit the start of file easily, we append this.
// And we need to TRIGGER it.
// We can attach another listener or check if DOM is ready.
// Safest: Attach a new listener that waits for parsing.
// --- ROBUST COMPARISON LOGIC V2 ---
async function initComparisonV2() {
    if (!testResult || !window.DB || !window.Auth) return;

    const user = Auth.getSession();
    if (!user) {
        document.getElementById('compare-bars-area').innerHTML = '<div class="empty-state">Please login to compare history.</div>';
        return;
    }

    try {
        const allAttempts = await DB.getAttemptsByUser(user.id);

        // Filter by same test ID
        const sameTestAttempts = allAttempts.filter(a => a.test_id === testResult.test_id);

        // Sort by date (Newest first)
        sameTestAttempts.sort((a, b) => new Date(b.submitted_at) - new Date(a.submitted_at));

        console.log("Debug Comparison Logic:", { current: testResult, history: sameTestAttempts });

        compareCurrent = testResult;
        comparePrevious = null; // Reset

        // ROBUST PREVIOUS SELECTION LOGIC
        // 1. Try to find the exact index of the current attempt in the DB history
        let currentIndex = -1;

        if (compareCurrent.id) {
            currentIndex = sameTestAttempts.findIndex(a => a.id === compareCurrent.id);
        }

        // Secondary Check: Timestamp + Score Match (if ID failed/missing)
        if (currentIndex === -1 && sameTestAttempts.length > 0) {
            const currentSub = new Date(compareCurrent.submitted_at || Date.now());

            // Check if index 0 is very close (e.g., just saved)
            const first = sameTestAttempts[0];
            const firstSub = new Date(first.submitted_at);
            const timeDiff = Math.abs(currentSub - firstSub);

            // Within 15 seconds AND score matches exactly
            if (timeDiff < 15000 && parseFloat(first.score) === parseFloat(compareCurrent.score)) {
                currentIndex = 0;
            }
        }

        console.log("Found Current at Index:", currentIndex);

        // 2. Select Previous
        if (currentIndex !== -1) {
            // If current is found at index N, previous is N+1
            if (sameTestAttempts.length > currentIndex + 1) {
                comparePrevious = sameTestAttempts[currentIndex + 1];
            }
        } else {
            // Fallback: Current not found in DB logic?
            // If we have history, assume we are viewing the latest result which IS index 0 (but match failed).
            // So Previous is index 1.
            if (sameTestAttempts.length > 1) {
                comparePrevious = sameTestAttempts[1];
            }
        }

        renderCompareChart('score');

    } catch (err) {
        console.error("Comparison Error:", err);
        document.getElementById('compare-bars-area').innerHTML = '<div class="empty-state">Could not load history.</div>';
    }
}

// Attach listener for V2
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initComparisonV2);
} else {
    initComparisonV2();
}

function toggleSidebar() {
    const sb = document.querySelector(".app-glass-sidebar");
    const ov = document.querySelector(".app-sidebar-overlay");
    if (sb) sb.classList.toggle("active");
    if (ov) ov.classList.toggle("active");
}
