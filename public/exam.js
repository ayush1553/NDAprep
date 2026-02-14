// EXAM LOGIC

// 1. Load Data
const questionsData = window.questionsData;

if (!questionsData || questionsData.length === 0) {
    console.error("Questions data not found!");
    alert("Error loading questions. Please try again.");
}

// 2. State Management
let currentQuestionIndex = 0;
let startTime = Date.now(); // Track Start Time
// State: 'not-visited', 'not-answered', 'answered', 'marked', 'marked-answered'
// answer: selected key (e.g. 'A') or null
let currentQuestionStartTime = Date.now();
let userResponses = questionsData.map(q => ({
    id: q.id,
    answer: null,
    status: 'not-visited',
    timeSpent: 0, // In seconds
    isBookmarked: false,
    isStarred: false
}));

// Check for Review Mode
const urlParams = new URLSearchParams(window.location.search);
const isReviewMode = urlParams.get('review') === 'true';

// Normal Mode Timer Initialization
// Normal Mode Timer Initialization
const currentTestType = urlParams.get('type') || 'PYQ';
let timeRemaining = (currentTestType === 'ChapterTest') ? 13 * 60 : 2 * 60 * 60 + 30 * 60; // Default 150 mins
if (currentTestType === 'Mock') {
    timeRemaining = 150 * 60; // Always 150 mins for Full Length Mock
}

function formatTime(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

if (isReviewMode) {
    const savedResult = JSON.parse(localStorage.getItem('ndaExamResult'));
    if (savedResult && savedResult.detailedResults) {
        // Restore responses
        userResponses = savedResult.detailedResults.map(r => ({
            id: r.id,
            answer: r.userAnswer || null,
            status: r.status // Restore status from exam
        }));

        document.body.classList.add('review-mode');
        // Disable timer or change text
        setTimeout(() => {
            const timerEl = document.querySelector('.exam-timer');
            if (timerEl) timerEl.innerHTML = '<span class="timer-icon">👁️</span> Review Mode';
            const submitBtn = document.querySelector('.btn-submit-exam');
            if (submitBtn) {
                submitBtn.textContent = 'Exit Review';
                submitBtn.onclick = () => window.location.href = 'index.html';
            }
        }, 100);

    } else {
        alert("No result found to review.");
        window.location.href = 'index.html';
    }
} else {
    // Start Global Timer
    const timerEl = document.getElementById('timer');

    const timerInterval = setInterval(() => {
        if (timeRemaining > 0) {
            timeRemaining--;
            if (timerEl) timerEl.textContent = formatTime(timeRemaining);

            // Increment per-question time
            userResponses[currentQuestionIndex].timeSpent++;
            updateQuestionTimerDisplay();
        } else {
            clearInterval(timerInterval);
            submitExam();
        }
    }, 1000);
}

function updateQuestionTimerDisplay() {
    const qTimerEl = document.getElementById('q-timer-text');
    if (qTimerEl) {
        const seconds = userResponses[currentQuestionIndex].timeSpent;
        const mm = String(Math.floor(seconds / 60)).padStart(2, '0');
        const ss = String(seconds % 60).padStart(2, '0');
        qTimerEl.textContent = `${mm}:${ss}`;
    }
}


// 3. Render Functions

function renderQuestion(index) {
    if (!isReviewMode) {
        // Update visited status if currently 'not-visited'
        if (userResponses[index].status === 'not-visited') {
            userResponses[index].status = 'not-answered';
            updatePaletteItem(index);
        }
    }

    const q = questionsData[index];
    const response = userResponses[index];

    // Update Header Metadata Info Row
    const qBadge = document.getElementById('q-number-badge');
    const qMarksPos = document.getElementById('q-marks-pos');
    const qMarksNeg = document.getElementById('q-marks-neg');
    const examNameDisplay = document.getElementById('exam-name-display');

    if (qBadge) qBadge.textContent = `${index + 1}`;
    if (qMarksPos) qMarksPos.textContent = `+ ${q.marks.toFixed(1)}`;
    if (qMarksNeg) qMarksNeg.textContent = `- ${Math.abs(q.negMarks).toFixed(1)}`;

    // Set Exam Name in Header
    if (examNameDisplay) {
        const subj = urlParams.get('subject') || 'Mathematics';
        const year = urlParams.get('year') || '2025';
        const chapterSlug = urlParams.get('chapter');

        if (currentTestType === 'ChapterTest') {
            const formattedChapter = chapterSlug ? chapterSlug.split('_').slice(1).map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ') : 'Chapter Test';
            examNameDisplay.textContent = `${formattedChapter} (CT)`;
        } else if (currentTestType === 'Mock') {
            const mockSlug = urlParams.get('slug');
            const formattedMock = mockSlug ? mockSlug.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ') : 'Mock Test';
            examNameDisplay.textContent = `${formattedMock}`;
        } else {
            examNameDisplay.textContent = `NDA ${year}: ${subj} Live ...`;
        }
    }

    // Update Action States in Info Row
    const bookmarkBtn = document.getElementById('btn-bookmark');
    const starBtn = document.getElementById('btn-star');

    if (bookmarkBtn) {
        bookmarkBtn.classList.toggle('active', !!userResponses[index].isBookmarked);
    }
    if (starBtn) {
        starBtn.classList.toggle('active', !!userResponses[index].isStarred);
    }

    // Sync Question Timer Display
    updateQuestionTimerDisplay();

    // Update Content using dynamic rendering
    const contentContainer = document.getElementById('question-content');
    if (contentContainer) {
        contentContainer.innerHTML = '';
        renderComplexQuestion(q, contentContainer);
    }

    // Sync Palette
    updatePaletteItem(index);

    // Update Buttons State
    const nextBtn = document.getElementById('btn-next');
    if (isReviewMode) {
        if (nextBtn) nextBtn.textContent = index === questionsData.length - 1 ? 'Finish Review' : 'Next Question';
    } else {
        if (nextBtn) nextBtn.textContent = index === questionsData.length - 1 ? 'Submit Test' : 'Save & Next';
    }

    // Render Options
    const optionsContainer = document.querySelector('.options-list');
    optionsContainer.innerHTML = '';
    optionsContainer.classList.remove('answered');

    if (isReviewMode) {
        optionsContainer.classList.add('answered'); // Lock interaction
    }

    for (const [key, value] of Object.entries(q.options)) {
        const optionLabel = document.createElement('label');
        optionLabel.className = 'option-item';

        let isChecked = response.answer === key;

        // Review Mode Logic
        if (isReviewMode) {
            // 1. Highlight Correct Answer
            if (key === q.correctAnswer) {
                optionLabel.classList.add('correct');
            }

            // 2. Highlight User Selection
            if (isChecked) {
                optionLabel.classList.add('selected');
                // If selected and wrong -> Incorrect
                if (key !== q.correctAnswer) {
                    optionLabel.classList.add('incorrect');
                }
            }
        } else {
            // Normal Mode
            if (isChecked) {
                optionLabel.classList.add('selected');
            }
        }

        optionLabel.dataset.key = key;

        optionLabel.innerHTML = `
            <input type="radio" name="q${q.id}" value="${key}" ${isChecked ? 'checked' : ''} ${isReviewMode ? 'disabled' : ''} style="display:none;">
            <span class="opt-label">${key}</span>
            <span class="opt-text">${value}</span>
        `;

        // Click Handler
        if (!isReviewMode) {
            optionLabel.addEventListener('click', function (e) {
                // Remove selected from others
                optionsContainer.querySelectorAll('.option-item').forEach(el => el.classList.remove('selected'));
                // Add to current
                this.classList.add('selected');

                userResponses[index].answer = key;

                if (userResponses[index].status === 'marked' || userResponses[index].status === 'marked-answered') {
                    userResponses[index].status = 'marked-answered';
                } else {
                    userResponses[index].status = 'answered';
                }
                updatePaletteItem(index);
            });
        }

        optionsContainer.appendChild(optionLabel);
    }

    // Highlight Palette Current
    document.querySelectorAll('.p-btn').forEach((btn, i) => {
        if (i === index) btn.classList.add('current');
        else btn.classList.remove('current');
    });
}

/**
 * Advanced Question Rendering: Instructions, Statements, Data Blocks
 */
function renderComplexQuestion(q, container) {
    // 1. Handle Explicit Directions field (Manual)
    if (q.direction) {
        const dirContainer = document.createElement('div');
        dirContainer.className = 'directions-container';

        const dirLabel = document.createElement('span');
        dirLabel.className = 'directions-label';
        dirLabel.textContent = 'Directions:';

        const dirText = document.createElement('div');
        dirText.className = 'directions-text';
        dirText.textContent = q.direction;

        dirContainer.appendChild(dirLabel);
        dirContainer.appendChild(dirText);
        container.appendChild(dirContainer);
    }

    const text = q.text;

    // 1. Detect Instruction (e.g., "Select the correct option.")
    // Usually instructions are before a colon or start with Directions/Consider/Select
    let instruction = "Select the most appropriate option.";
    let mainBody = text;

    const instructionsPatterns = [
        "Directions:", "Consider the following", "Choose the correct", "Select the correct", "Match List", "Assertion (A):"
    ];

    for (let pattern of instructionsPatterns) {
        if (text.startsWith(pattern)) {
            // Found specific instruction
            const splitIdx = text.indexOf('\n') !== -1 ? text.indexOf('\n') : text.indexOf('.');
            if (splitIdx !== -1) {
                instruction = text.substring(0, splitIdx + 1);
                mainBody = text.substring(splitIdx + 1).trim();
            }
            break;
        }
    }

    // Add Instruction Line
    const instEl = document.createElement('span');
    instEl.className = 'instruction-line';
    instEl.textContent = instruction;
    container.appendChild(instEl);

    // 2. Handle Data Blocks (Statements, Tables, Lists)
    // Detect Statement-based (1. ..., 2. ...)
    const statementRegex = /(?:\d+\.|\b[IVX]+\.)\s+[^\n]+/g;
    const matches = mainBody.match(statementRegex);

    if (matches && matches.length > 1) {
        // Extract the part before the statements
        const firstMatchIdx = mainBody.indexOf(matches[0]);
        const questionIntro = mainBody.substring(0, firstMatchIdx).trim();
        const questionConclusion = mainBody.substring(mainBody.lastIndexOf(matches[matches.length - 1]) + matches[matches.length - 1].length).trim();

        if (questionIntro) {
            const introEl = document.createElement('div');
            introEl.className = 'question-text';
            introEl.textContent = questionIntro;
            container.appendChild(introEl);
        }

        const dataBlock = document.createElement('div');
        dataBlock.className = 'data-block';
        const list = document.createElement('ul');
        list.className = 'statement-list';

        matches.forEach(m => {
            const item = document.createElement('li');
            item.className = 'statement-item';
            // Separate Number and Text
            const dotIdx = m.indexOf('.');
            const num = m.substring(0, dotIdx + 1);
            const content = m.substring(dotIdx + 1).trim();

            item.innerHTML = `<span class="statement-num">${num}</span> <span class="statement-txt">${content}</span>`;
            list.appendChild(item);
        });

        dataBlock.appendChild(list);
        container.appendChild(dataBlock);

        if (questionConclusion) {
            const concEl = document.createElement('div');
            concEl.className = 'question-text';
            concEl.textContent = questionConclusion;
            container.appendChild(concEl);
        }
    }
    // Detect Assertion-Reason
    else if (mainBody.includes("Assertion (A):") || mainBody.includes("Reason (R):")) {
        const dataBlock = document.createElement('div');
        dataBlock.className = 'data-block';

        const assertionMatch = mainBody.match(/Assertion \(A\):?([\s\S]+?)(?=Reason \(R\):|$)/i);
        const reasonMatch = mainBody.match(/Reason \(R\):?([\s\S]+?)$/i);

        if (assertionMatch) {
            const p = document.createElement('p');
            p.className = 'statement-item';
            p.innerHTML = `<span class="statement-num">Assertion (A):</span> ${assertionMatch[1].trim()}`;
            dataBlock.appendChild(p);
        }
        if (reasonMatch) {
            const p = document.createElement('p');
            p.className = 'statement-item';
            p.innerHTML = `<span class="statement-num">Reason (R):</span> ${reasonMatch[1].trim()}`;
            dataBlock.appendChild(p);
        }
        container.appendChild(dataBlock);
    }
    // Standard Question Text
    else {
        const textEl = document.createElement('div');
        textEl.className = 'question-text';
        textEl.textContent = mainBody;
        container.appendChild(textEl);
    }

    // 3. Handle Images
    if (q.image) {
        const img = document.createElement('img');
        img.src = q.image;
        img.alt = "Question Image";
        img.onclick = () => openImageModal(img.src, "Question Illustration");
        container.appendChild(img);
    }
}

// Image Modal Handler
function openImageModal(src, caption) {
    const modal = document.getElementById('image-modal');
    const modalImg = document.getElementById("img-expanded");
    const captionText = document.getElementById("modal-caption");

    modal.style.display = "block";
    modalImg.src = src;
    captionText.innerHTML = caption;

    const span = document.getElementsByClassName("close-modal")[0];
    span.onclick = function () {
        modal.style.display = "none";
    };

    window.onclick = function (event) {
        if (event.target == modal) {
            modal.style.display = "none";
        }
    };
}

function initPalette() {
    const paletteGrid = document.getElementById('palette-grid');
    if (!paletteGrid) return;
    paletteGrid.innerHTML = '';

    questionsData.forEach((q, i) => {
        const btn = document.createElement('button');
        btn.className = 'p-btn';

        // Initial state
        const status = userResponses[i].status;
        btn.classList.add(status);
        if (i === currentQuestionIndex) btn.classList.add('current');

        btn.textContent = i + 1;
        btn.onclick = () => {
            currentQuestionIndex = i;
            renderQuestion(currentQuestionIndex);
        };
        paletteGrid.appendChild(btn);
    });

    updatePaletteCounts();
}

function updatePaletteItem(index) {
    if (isReviewMode) return;

    const paletteGrid = document.getElementById('palette-grid');
    if (!paletteGrid) return;

    // Refresh all to handle 'current' status properly
    const buttons = paletteGrid.querySelectorAll('.p-btn');
    buttons.forEach((btn, i) => {
        const status = userResponses[i].status;
        btn.className = 'p-btn';
        btn.classList.add(status);
        if (i === currentQuestionIndex) btn.classList.add('current');
    });

    updatePaletteCounts();
}

function updatePaletteCounts() {
    const counts = {
        marked: 0,
        attempted: 0,
        unattempted: 0,
        unseen: 0
    };

    userResponses.forEach(r => {
        if (r.status === 'marked' || r.status === 'marked-answered') counts.marked++;
        else if (r.status === 'answered') counts.attempted++;
        else if (r.status === 'not-answered') counts.unattempted++;
        else if (r.status === 'not-visited') counts.unseen++;
    });

    if (document.getElementById('count-marked')) document.getElementById('count-marked').textContent = counts.marked;
    if (document.getElementById('count-attempted')) document.getElementById('count-attempted').textContent = counts.attempted;
    if (document.getElementById('count-unattempted')) document.getElementById('count-unattempted').textContent = counts.unattempted;
    if (document.getElementById('count-unseen')) document.getElementById('count-unseen').textContent = counts.unseen;
}


// 4. Interaction Handlers

// Previous
const btnPrev = document.getElementById('btn-prev');
if (btnPrev) {
    btnPrev.addEventListener('click', () => {
        if (currentQuestionIndex > 0) {
            currentQuestionIndex--;
            renderQuestion(currentQuestionIndex);
        }
    });
}

// Save & Next (or Submit)
const btnNext = document.getElementById('btn-next');
if (btnNext) {
    btnNext.addEventListener('click', () => {
        if (isReviewMode) {
            if (currentQuestionIndex === questionsData.length - 1) {
                window.location.href = 'index.html';
            } else {
                currentQuestionIndex++;
                renderQuestion(currentQuestionIndex);
            }
            return;
        }

        // Normal Mode: Save & Next
        if (currentQuestionIndex === questionsData.length - 1) {
            submitExam();
            return;
        }

        // Transition logic
        const resp = userResponses[currentQuestionIndex];
        if (resp.answer !== null) {
            resp.status = resp.isStarred ? 'marked-answered' : 'answered';
        } else {
            resp.status = resp.isStarred ? 'marked' : 'not-answered';
        }
        updatePaletteItem(currentQuestionIndex);

        currentQuestionIndex++;
        renderQuestion(currentQuestionIndex);
    });
}


// 5. Submission
function submitExam() {
    if (isReviewMode) return;

    // Calculate Stats for Modal
    let attempted = 0;
    let marked = 0;
    let unattempted = 0;

    userResponses.forEach(r => {
        if (r.status === 'answered' || r.status === 'marked-answered') {
            attempted++;
        } else if (r.status === 'not-answered') {
            unattempted++;
        } else if (r.status === 'marked') {
            marked++;
        } else if (r.status === 'not-visited') {
            unattempted++; // Unseen counts as unattempted for simplified summary in modal
        }
    });

    // Populate Modal Info
    const modalTimeEl = document.getElementById('modal-time-left');
    const modalAttemptedEl = document.getElementById('modal-attempted');
    const modalUnattemptedEl = document.getElementById('modal-unattempted');
    const modalMarkedEl = document.getElementById('modal-marked');
    const timerEl = document.getElementById('timer');

    if (modalTimeEl && timerEl) modalTimeEl.textContent = formatTime(timeRemaining);
    if (modalAttemptedEl) modalAttemptedEl.textContent = attempted;
    if (modalUnattemptedEl) modalUnattemptedEl.textContent = unattempted;
    if (modalMarkedEl) modalMarkedEl.textContent = marked;

    // Show Modal
    const modal = document.getElementById('submit-modal');
    if (modal) modal.style.display = 'flex';
}

async function finishTest() {
    // Stop and Calculate Time
    const endTime = Date.now();
    const timeTakenSeconds = Math.floor((endTime - startTime) / 1000);

    // Calculate Result
    let correctCount = 0;
    let incorrectCount = 0;
    let score = 0;
    let totalNegative = 0;

    const detailedResults = userResponses.map((r, i) => {
        const q = questionsData[i];
        let isCorrect = false;

        if (r.answer) {
            if (r.answer === q.correctAnswer) {
                isCorrect = true;
                correctCount++;
                score += q.marks;
            } else {
                incorrectCount++;
                const negVal = Math.abs(q.negMarks);
                score -= negVal;
                totalNegative += negVal;
            }
        }

        return {
            id: q.id,
            userAnswer: r.answer,
            correctAnswer: q.correctAnswer,
            isCorrect: isCorrect,
            status: r.status
        };
    });

    // Save to Database
    const session = window.Auth ? window.Auth.getSession() : null;
    const accuracy = ((correctCount / attemptedCount()) * 100 || 0).toFixed(1);

    const attemptData = {
        user_id: session ? session.id : 'guest',
        test_id: currentTestType === 'ChapterTest' ? `ct_${urlParams.get('chapter')}` :
            (currentTestType === 'Mock' ? `mock_${urlParams.get('slug')}` : `nda_${urlParams.get('year') || '2022'}_${urlParams.get('session') || '2'}`),
        test_type: currentTestType,
        subject: urlParams.get('subject') || 'Mathematics',
        year: currentTestType === 'Mock' ? '2026' : (urlParams.get('year') || '2022'),
        session: currentTestType === 'Mock' ? '1' : (urlParams.get('session') || '2'),
        total_questions: questionsData.length,
        attempted: attemptedCount(),
        correct: correctCount,
        incorrect: incorrectCount,
        unattempted: questionsData.length - attemptedCount(),
        score: score.toFixed(2),
        max_score: (function () {
            if (currentTestType === 'ChapterTest') {
                // MAT = 2.5, GAT = 4.0
                const marksPerQ = (urlParams.get('subject') === 'Mathematics') ? 2.5 : 4.0;
                return (questionsData.length * marksPerQ).toFixed(0);
            } else if (urlParams.get('subject') === 'GAT' || (urlParams.get('subject') && urlParams.get('subject').includes('GAT'))) {
                return (questionsData.length * 4.0).toFixed(0);
            } else {
                return (questionsData.length * 2.5).toFixed(0);
            }
        })(),
        accuracy: accuracy,
        time_taken: timeTakenSeconds,
        detailedResults: detailedResults
    };

    // Store in DB
    try {
        const savedAttempt = await DB.saveAttempt(attemptData);
        // Save as current result for result.html to pick up
        localStorage.setItem('ndaExamResult', JSON.stringify(savedAttempt));
        // Redirect
        window.location.href = 'result.html';
    } catch (err) {
        console.error('DB Error:', err);
        alert('Failed to save result: ' + err.message);
    }
}

function attemptedCount() {
    return userResponses.filter(r => r.answer !== null).length;
}


// 6. UI Initializers
function initResponsiveHandlers() {
    const toggleBtn = document.getElementById('palette-toggle');
    const panel = document.querySelector('.palette-panel');
    const backdrop = document.getElementById('palette-backdrop');

    if (toggleBtn && panel && backdrop) {
        toggleBtn.onclick = () => {
            panel.classList.toggle('active');
            backdrop.classList.toggle('active');
        };

        backdrop.onclick = () => {
            panel.classList.remove('active');
            backdrop.classList.remove('active');
        };

        const grid = document.getElementById('palette-grid');
        if (grid) {
            grid.onclick = (e) => {
                if (e.target.classList.contains('p-btn') && window.innerWidth <= 1024) {
                    panel.classList.remove('active');
                    backdrop.classList.remove('active');
                }
            };
        }
    }
}

function initActionListeners() {
    // Bookmark Toggle
    const btnBookmark = document.getElementById('btn-bookmark');
    if (btnBookmark) {
        btnBookmark.onclick = () => {
            userResponses[currentQuestionIndex].isBookmarked = !userResponses[currentQuestionIndex].isBookmarked;
            btnBookmark.classList.toggle('active', !!userResponses[currentQuestionIndex].isBookmarked);
        };
    }

    // Star Toggle (Info Row) - Fix: Ensure state persists and palette updates
    const btnStar = document.getElementById('btn-star');
    if (btnStar) {
        btnStar.onclick = () => {
            const resp = userResponses[currentQuestionIndex];
            resp.isStarred = !resp.isStarred;
            btnStar.classList.toggle('active', !!resp.isStarred);

            // Sync with question status logic
            if (resp.answer) {
                resp.status = resp.isStarred ? 'marked-answered' : 'answered';
            } else {
                resp.status = resp.isStarred ? 'marked' : 'not-answered';
            }
            updatePaletteItem(currentQuestionIndex);
        };
    }

    // View Instructions (Palette)
    const btnViewIns = document.querySelector('.palette-instructions');
    if (btnViewIns) {
        btnViewIns.onclick = () => {
            const modal = document.getElementById('instructions-modal');
            if (modal) modal.style.display = 'block';
        };
    }

    // Close Instructions / Proceed
    const btnCloseIns = document.getElementById('btn-close-instructions');
    if (btnCloseIns) {
        btnCloseIns.onclick = () => {
            const modal = document.getElementById('instructions-modal');
            if (modal) modal.style.display = 'none';
        };
    }

    // Submit Modal: Yes
    const btnSubmitYes = document.getElementById('btn-submit-confirm-yes');
    if (btnSubmitYes) {
        btnSubmitYes.onclick = () => {
            finishTest();
        };
    }

    // Submit Modal: No
    const btnSubmitNo = document.getElementById('btn-submit-confirm-no');
    if (btnSubmitNo) {
        btnSubmitNo.onclick = () => {
            const modal = document.getElementById('submit-modal');
            if (modal) modal.style.display = 'none';
        };
    }

    // Mark & Next (Bottom Bar)
    const btnMarkExtra = document.getElementById('btn-mark-extra');
    if (btnMarkExtra) {
        btnMarkExtra.onclick = () => {
            if (isReviewMode) return;
            const resp = userResponses[currentQuestionIndex];
            resp.isStarred = true; // Setting starred state

            if (resp.answer) {
                resp.status = 'marked-answered';
            } else {
                resp.status = 'marked';
            }
            updatePaletteItem(currentQuestionIndex);

            // Move to next question if not last
            if (currentQuestionIndex < questionsData.length - 1) {
                currentQuestionIndex++;
                renderQuestion(currentQuestionIndex);
            }
        };
    }

    // Clear (Bottom Bar)
    const btnClearExtra = document.getElementById('btn-clear-extra');
    if (btnClearExtra) {
        btnClearExtra.onclick = () => {
            if (isReviewMode) return;
            const resp = userResponses[currentQuestionIndex];
            resp.answer = null;
            resp.status = 'not-answered';

            const container = document.querySelector('.options-list');
            if (container) {
                container.querySelectorAll('input').forEach(i => i.checked = false);
                container.querySelectorAll('.option-item').forEach(el => el.classList.remove('selected'));
            }
            updatePaletteItem(currentQuestionIndex);
        };
    }

    // Submit Test (Palette Footer)
    const btnSubmitPalette = document.querySelector('.btn-submit-palette');
    if (btnSubmitPalette) {
        btnSubmitPalette.onclick = () => {
            submitExam();
        };
    }
}

// Initialize
initPalette();
renderQuestion(0);
initResponsiveHandlers();
initActionListeners();
