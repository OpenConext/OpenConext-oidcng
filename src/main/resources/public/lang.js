function switchLang(lang) {
    const searchParams = new URLSearchParams(window.location.search);
    searchParams.set("lang", lang);
    window.location.search = searchParams.toString();
}
