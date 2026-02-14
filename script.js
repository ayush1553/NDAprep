document.addEventListener('DOMContentLoaded', () => {
    // --- SUBJECT PAGE LOGIC ---


    // 1. Sidebar Toggle (Tree view)
    const treeHeaders = document.querySelectorAll('.tree-header');
    treeHeaders.forEach(header => {
        header.addEventListener('click', (e) => {
            const parent = header.parentElement;
            parent.classList.toggle('active');

            // Toggle Chevron
            const chevron = header.querySelector('.chevron');
            if (chevron) {
                if (chevron.classList.contains('expanded')) {
                    chevron.classList.remove('expanded');
                    if (chevron.textContent === '▼') chevron.textContent = '▶';
                } else {
                    chevron.classList.add('expanded');
                    if (chevron.textContent === '▶') chevron.textContent = '▼';
                }
            }
        });
    });

    // 2. Mobile Sidebar Drawer
    const sidebarToggleBtn = document.querySelector('.sidebar-toggle-btn');
    const sidebar = document.querySelector('.syllabus-sidebar');

    if (sidebarToggleBtn && sidebar) {
        sidebarToggleBtn.addEventListener('click', (e) => {
            e.stopPropagation(); // Prevent immediate closing
            sidebar.classList.toggle('active');
        });

        // Close sidebar when clicking outside
        document.addEventListener('click', (e) => {
            if (sidebar.classList.contains('active') &&
                !sidebar.contains(e.target) &&
                !sidebarToggleBtn.contains(e.target)) {
                sidebar.classList.remove('active');
            }
        });
    }

    // 3. Tab Switching
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabPanels = document.querySelectorAll('.tab-panel');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active class from all
            tabBtns.forEach(b => b.classList.remove('active'));
            tabPanels.forEach(p => p.classList.remove('active'));

            // Add active class to clicked
            btn.classList.add('active');
            const tabId = btn.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
        });
    });

    // 5. Chapter Test GAT Discipline Selector
    const disciplineBtns = document.querySelectorAll('.discipline-btn');
    const gatCtList = document.getElementById('gat-ct-list');

    if (disciplineBtns.length > 0 && gatCtList) {
        disciplineBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                // Update active button
                disciplineBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');

                const discipline = btn.getAttribute('data-discipline');
                updateGatTests(discipline);
            });
        });
    }

    function updateGatTests(discipline) {
        // Placeholder logic to show filtering effect
        // In a real app, this would fetch from a data object
        let testsHtml = '';

        if (discipline === 'English') {
            testsHtml = `
                    <div class="ct-card">
                        <div class="ct-card-main">
                            <div class="ct-info">
                                <div class="ct-badges"><span class="ct-badge-free">Free</span></div>
                                <div class="ct-name">UPSC NDA 01/2026: CT 01: Synonyms</div>
                                <div class="ct-meta">10 Qs · 10 mins · 40.0 Marks</div>
                            </div>
                            <div class="ct-cta">Start Test</div>
                        </div>
                        <div class="ct-footer-strip">
                            <span class="ct-lang">Language: English</span>
                        </div>
                    </div>
                `;
        } else {
            testsHtml = `
                    <div class="ct-card">
                        <div class="ct-card-main">
                            <div class="ct-info">
                                <div class="ct-name">${discipline} Test coming soon</div>
                                <div class="ct-meta">Metadata will appear here</div>
                            </div>
                            <div class="ct-cta coming-soon">Coming Soon</div>
                        </div>
                    </div>
                `;
        }

        gatCtList.innerHTML = testsHtml;
    }
    // --- PERFORMANCE DASHBOARD (Home Page) ---
    async function loadHomePerformance() {
        const user = Auth.getSession();
        if (!user) return;

        try {
            const summary = await DB.getPerformanceSummary(user.id);
            if (summary) {
                document.getElementById('total-attempts').textContent = summary.totalTests;
                document.getElementById('avg-accuracy').textContent = summary.avgAccuracy + '%';

                // Fetch highest score from all attempts
                const attempts = await DB.getAttemptsByUser(user.id);
                if (attempts.length > 0) {
                    const topScore = Math.max(...attempts.map(a => parseFloat(a.score)));
                    document.getElementById('top-score').textContent = topScore;
                    document.getElementById('perf-hint').textContent = `Great job! Your current average accuracy is ${summary.avgAccuracy}%.`;
                }
            }
        } catch (err) {
            console.error('Failed to load performance summary:', err);
        }
    }

    // Initialize home performance if on index.html
    if (document.querySelector('.performance-card')) {
        loadHomePerformance();
    }
});
