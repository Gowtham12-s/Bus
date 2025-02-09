function toggleMenu() {
    let menu = document.getElementById("sideMenu");
    if (menu.style.width === "250px") {
        menu.style.width = "0";  // Close Menu
    } else {
        menu.style.width = "250px";  // Open Menu
    }
}
