window.handleState = function handleState() {
  if (document.readyState === 'interactive' || document.readyState === "complete") {
    document.forms[0].submit();
  }
};
document.onreadystatechange = window.handleState;
