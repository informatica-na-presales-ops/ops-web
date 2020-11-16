function format_duration(m) {
    // Change number of milliseconds to 'HH:MM:SS'
    const total_seconds = Math.floor(m / 1000);
    let hours = Math.floor(total_seconds / 3600);
    let minutes = Math.floor((total_seconds - (hours * 3600)) / 60);
    let seconds = total_seconds - (hours * 3600) - (minutes * 60);
    if (hours < 10) {
        hours = `0${hours}`;
    }
    if (minutes < 10) {
        minutes = `0${minutes}`;
    }
    if (seconds < 10) {
        seconds = `0${seconds}`;
    }
    return `${hours}:${minutes}:${seconds}`;
}

function update_elapsed_time() {
    const step_title = document.getElementById('step-title');
    if (step_title !== null) {
        const start_value = parseInt(step_title.dataset.stepStartTime);
        const start = new Date(start_value);
        const end = Date.now();
        const elapsed = end - start;
        document.getElementById('step-elapsed-time').textContent = format_duration(elapsed);
    }
}

// 1000 milliseconds is 1 second
setInterval(update_elapsed_time, 1000);

// add target="_blank" to any <a> elements in rendered markdown
document.querySelectorAll('.rendered a').forEach(function (el) {
    el.target = '_blank';
});
