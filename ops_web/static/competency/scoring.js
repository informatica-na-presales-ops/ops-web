window.found_invalid = false;

document.querySelectorAll('input[type=radio]').forEach(function (el) {

    el.addEventListener('change', function () {
        // reset the invalid input search
        window.found_invalid = false;

        const competency_id = this.dataset.competencyId;

        // get the current score
        let current_score = 0;
        const current_badge = document.getElementById(`badge-${competency_id}-current`);
        if (current_badge) {
            current_score = parseInt(current_badge.textContent);
            if (isNaN(current_score)) {
                current_score = 0;
            }
        }

        // get the new score
        const new_score = this.value;

        // show (or hide) the score delta
        const delta_el = document.getElementById(`delta-${competency_id}`);
        const new_badge = document.getElementById(`badge-${competency_id}-new`);
        if (current_score === 0) {
            delta_el.classList.remove('show');
            new_badge.classList.remove('badge-danger', 'badge-success');
            new_badge.classList.add('badge-light', 'show');
        } else if (new_score > current_score) {
            delta_el.classList.remove('oi-arrow-bottom');
            delta_el.classList.add('oi-arrow-top', 'show');
            new_badge.classList.remove('badge-danger', 'badge-light');
            new_badge.classList.add('badge-success', 'show');
        } else if (new_score < current_score) {
            delta_el.classList.remove('oi-arrow-top');
            delta_el.classList.add('oi-arrow-bottom', 'show');
            new_badge.classList.remove('badge-light', 'badge-success');
            new_badge.classList.add('badge-danger', 'show');
        } else {
            new_badge.classList.remove('show');
        }

        document.getElementById(`score-${competency_id}`).textContent = new_score;
    });

    el.addEventListener('invalid', function () {
        // find the first hidden invalid element and show the tab for it
        if (window.found_invalid) {
            return;
        }
        const pill = document.querySelector(`a[href='#${el.name}']`);
        pill.click();
        window.found_invalid = true;
    });

});
