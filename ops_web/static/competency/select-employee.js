// when the employee selection changes, navigate to the page in data-target
document.getElementById('select-employee').addEventListener('change', function () {
    const selected_option = this.options[this.selectedIndex];
    window.location.href = selected_option.dataset.target;
});
