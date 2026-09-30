/* CBT-Kenya student dashboard behaviour. Server values arrive via window.APP (set in student.php). */
(function () {
    'use strict';

    var ALL_SECTIONS = [
        'dashboardContent','coursesSection','browseCoursesSection','progressSection','certificatesSection',
        'paymentsSection','attendanceSection','notificationsSection','bookmarksSection','ticketSection',
        'resourceHubSection','referralsSection','cpdSection','logbookSection','jobsSection','forumsSection',
        'alumniSection','portfolioSection','profileSection','settingsSection'
    ];

    /* Sidebar */
    window.toggleSidebar = function () {
        document.getElementById('sidebar').classList.toggle('open');
        document.getElementById('sidebarOverlay').classList.toggle('active');
    };
    window.closeSidebar = function () {
        document.getElementById('sidebar').classList.remove('open');
        document.getElementById('sidebarOverlay').classList.remove('active');
    };

    /* Sections */
    function navLinkFor(id) {
        return document.querySelector('#navMenu li a[data-section="' + id + '"]');
    }
    window.showSection = function (id, linkEl) {
        ALL_SECTIONS.forEach(function (s) {
            var el = document.getElementById(s);
            if (el) el.style.display = 'none';
        });
        var target = document.getElementById(id);
        if (target) target.style.display = 'block';

        document.querySelectorAll('#navMenu li').forEach(function (li) { li.classList.remove('active'); });
        var link = linkEl || navLinkFor(id);
        if (link) link.closest('li').classList.add('active');

        closeSidebar();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    };

    window.addEventListener('load', function () {
        showSection((window.APP && window.APP.activeSection) || 'dashboardContent');
        window.scrollTo(0, 0);
    });

    /* Modals */
    window.openModal = function (id) {
        document.getElementById(id).classList.add('active');
        document.body.style.overflow = 'hidden';
    };
    window.closeModal = function (id) {
        document.getElementById(id).classList.remove('active');
        document.body.style.overflow = '';
    };
    document.addEventListener('click', function (e) {
        if (e.target.classList && e.target.classList.contains('modal-overlay')) closeModal(e.target.id);
    });
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal-overlay.active').forEach(function (m) { closeModal(m.id); });
        }
    });

    /* Set a modal title safely (user-supplied text goes in via textContent, never innerHTML) */
    function setModalTitle(id, iconClass, text) {
        var el = document.getElementById(id);
        el.textContent = '';
        var i = document.createElement('i');
        i.className = iconClass;
        el.appendChild(i);
        el.appendChild(document.createTextNode(' ' + text));
    }

    window.openJobApplyModal = function (jobId, jobTitle) {
        document.getElementById('jobApplyJobId').value = jobId;
        setModalTitle('jobApplyTitle', 'fas fa-paper-plane', 'Apply - ' + jobTitle);
        openModal('jobApplyModal');
    };

    window.openMentorRequestModal = function (mentorUserId, mentorName) {
        document.getElementById('mentorRequestMentorId').value = mentorUserId;
        setModalTitle('mentorRequestTitle', 'fas fa-hand-holding-heart', 'Request Mentorship - ' + mentorName);
        openModal('mentorRequestModal');
    };

    window.openPortfolioEdit = function (id, title, category, description, isPublic) {
        document.getElementById('portfolioEditId').value = id;
        document.getElementById('portfolioEditTitle').value = title;
        document.getElementById('portfolioEditCategory').value = category;
        document.getElementById('portfolioEditDescription').value = description;
        document.getElementById('portfolioEditPublic').checked = !!isPublic;
        openModal('portfolioEditModal');
    };

    /* Referral link copy */
    window.copyReferralLink = function () {
        var input = document.getElementById('referralLinkInput');
        if (!input || !input.value) return;
        input.select();
        input.setSelectionRange(0, 99999);

        function finish(ok) {
            var btn = document.querySelector('.referral-link-box .btn');
            if (!btn) return;
            var original = btn.innerHTML;
            btn.innerHTML = ok ? '<i class="fas fa-check"></i> Copied!' : '<i class="fas fa-times"></i> Copy failed';
            setTimeout(function () { btn.innerHTML = original; }, 1800);
        }
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(input.value).then(function () { finish(true); }, function () { finish(false); });
        } else {
            try { finish(document.execCommand('copy')); } catch (err) { finish(false); }
        }
    };
})();