const computeNextRun = (freq, t, days, mDay, tzOffset = 0) => {
    const now = new Date();
    // Simulate server being in UTC by defining now as UTC explicit
    const serverNowUTC = Date.UTC(2026, 3, 14, 14, 5, 27); // 14:05:27 UTC (19:35 IST)
    
    // Replace "now" with a constructed date representing the current exact moment
    const serverNow = new Date(serverNowUTC); 
    
    const localNow = new Date(serverNow.getTime() - tzOffset * 60000);
    const [hours, minutes] = t.split(':').map(Number); // 19:40
    
    let nextLocal = new Date(Date.UTC(localNow.getUTCFullYear(), localNow.getUTCMonth(), localNow.getUTCDate(), hours, minutes, 0));

    console.log("localNow UTC string:", new Date(localNow).toISOString());
    console.log("nextLocal UTC string:", new Date(nextLocal).toISOString());

    if (nextLocal <= localNow) {
        console.log("Next local is <= localNow, advancing a day");
        if (freq === 'daily') nextLocal.setUTCDate(nextLocal.getUTCDate() + 1);
        else if (freq === 'weekly') {
            nextLocal.setUTCDate(nextLocal.getUTCDate() + 1);
        } else if (freq === 'monthly') nextLocal.setUTCMonth(nextLocal.getUTCMonth() + 1);
    } else {
        console.log("Next local is > localNow, NOT advancing a day");
    }

    return new Date(nextLocal.getTime() + tzOffset * 60000);
};

// IST offset = -330
const nextRun = computeNextRun('daily', '19:40', [], null, -330);
console.log("Result True UTC Time:", nextRun.toISOString());
// At 14:05 UTC (19:35 IST), the user selects 19:40 IST (14:10 UTC).
// Result should be 14:10 UTC today (since 14:10 > 14:05).
