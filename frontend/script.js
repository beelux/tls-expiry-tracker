function generateTable(data) {
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
        const dateText = document.createTextNode(data[i].date + " days ago");
        date.appendChild(dateText);
        row.appendChild(date);

        tableBody.appendChild(row);
    }

    const table = document.createElement("table");
    table.classList.add("logs__table");
    table.appendChild(tableBody);
    document.getElementById("logs").appendChild(table);
}

fetch("data.json").then(res => res.json()).then(data => generateTable(data.incidents));