document.addEventListener('DOMContentLoaded', function() {
    const countdownElementDashboard = document.getElementById('countdown-redirect-dashboard');

    if (countdownElementDashboard) {
        redirectDashboardCountdown();
    }
});

let redirectTimerDashboardInterval = null;

function redirectDashboardCountdown(){
    const countdownElementDashboard = document.getElementById('countdown-redirect-dashboard');

    if (redirectTimerDashboardInterval) {
        clearInterval(redirectTimerDashboardInterval);
    }

    let timeLeft = 10;

    redirectTimerDashboardInterval = setInterval(function () {
        timeLeft -= 1;
        countdownElementDashboard.textContent = timeLeft;

        if (timeLeft <=0) {
            clearInterval(redirectTimerDashboardInterval);
            window.location.href = '/dashboard';
        }
    }, 1000);

}