function getDateDifference(datePosix) {
    const difference = Date.now() - (datePosix * 1000);
    const days = Math.floor(difference / (1000 * 3600 * 24));
    return days.toString();
}

function generateTable(data) {
    try {
    const tableBody = document.createElement("tbody");
    tableBody.classList.add("logs__tbody");

    for (let i = 0; i < data.length; i++) {
        const row = document.createElement("tr");
        row.classList.add("logs__trow");

        const domain = document.createElement("td");
        domain.classList.add("logs__item__name");
        const domainText = document.createTextNode(data[i].domain);
        domain.appendChild(domainText);
        row.appendChild(domain);

        const date = document.createElement("td");
        date.classList.add("logs__item__date");
        const dateData = getDateDifference(data[i].date);
        const dateText = document.createTextNode(dateData + " days ago");
        date.appendChild(dateText);
        row.appendChild(date);

        tableBody.appendChild(row);
    }

    const table = document.createElement("table");
    table.classList.add("logs__table");
    table.id = "logs__table";
    table.appendChild(tableBody);
    document.getElementById("logs__table").replaceWith(table);
    } catch (e) {}
}

function setRecentDate(data) {
    console.log(data);
    let mostRecentDate = 0;
    try {
        mostRecentDate = data.reduce((maxNum, expiredEntry) => {
            return Math.max(expiredEntry.date, maxNum)
        }, 0);
    } catch (e) {}

    if(mostRecentDate === 0) mostRecentDate = "∞";
    else mostRecentDate = getDateDifference(mostRecentDate);

    document.getElementById("time__tls").innerHTML = mostRecentDate;
}

fetch("data.json")
    .then(res => res.json())
    .then(data => {
        generateTable(data.incidents);
        setRecentDate(data.incidents);
    });