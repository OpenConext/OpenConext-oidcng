document.addEventListener("DOMContentLoaded", function () {
    var inputField = document.getElementById("userCode");
    inputField.oninput = function (e) {
        var value = e.target.value;
        var newValue = this.value.toUpperCase();
        if (value.length === 4 && e.inputType === "insertText" && !value.endsWith("-")) {
            newValue += "-";
        }
        this.value = newValue;
    }
});
