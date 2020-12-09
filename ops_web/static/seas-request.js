function on_change_primary_product() {
    const selected_option = this.options[this.selectedIndex];
    const primary_product_name_input = document.getElementById('primary-product-name');
    primary_product_name_input.value = selected_option.text;
}

document.getElementById('primary-product').addEventListener('change', on_change_primary_product);
