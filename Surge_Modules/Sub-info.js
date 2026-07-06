/**********
* Author: cc63 & ChatGPT & Claude
* Updated: 2025-05-03
**********/

(async () => {
  try {
    // Read arguments and process the data
    const args = getArgs();
    const info = await getDataInfo(args.url);

    // If there is no info, finish immediately
    if (!info) return $done({});

    // Handle the reset day and expiry date
    const resetDayLeft = args.reset_day ? getRemainingDays(parseInt(args.reset_day)) : null;
    const expireDate = args.expire || info.expire;
    const expireDaysLeft = getExpireDaysLeft(expireDate);

    // Compute data usage
    const used = info.download + info.upload;
    const total = info.total;
    const content = [`Usage: ${bytesToSize(used)} / ${bytesToSize(total)}`];

    // Build the notification lines
    buildNotifications(content, used, total, resetDayLeft, expireDaysLeft, expireDate);

    // Return the result
    $done({
      title: args.title,
      content: content.join("\n"),
      icon: args.icon || "tornado",
      "icon-color": args.color || "#DF4688",
    });
  } catch (error) {
    console.log(`Error occurred: ${error}`);
    $done({
      title: "Failed to fetch subscription info",
      content: `Error: ${error}`,
      icon: "exclamationmark.triangle",
      "icon-color": "#CB1B45",
    });
  }
})();

/**
 * Build the notification content
 */
function buildNotifications(content, used, total, resetDayLeft, expireDaysLeft, expireDate) {
  // Check whether this is an unlimited-time plan
  if (!resetDayLeft && !expireDaysLeft) {
    const percentage = ((used / total) * 100).toFixed(1);
    content.push(`Notice: ${percentage}% of data used`);
    return;
  }

  // Add reset and expiry reminders
  if (resetDayLeft && expireDaysLeft) {
    content.push(`Notice: resets in ${resetDayLeft} day(s), expires in ${expireDaysLeft} day(s)`);
  } else if (resetDayLeft) {
    content.push(`Notice: data resets in ${resetDayLeft} day(s)`);
  } else if (expireDaysLeft) {
    content.push(`Notice: plan expires in ${expireDaysLeft} day(s)`);
  }

  // Add the expiry date
  if (expireDaysLeft) {
    content.push(`Expires: ${formatTime(expireDate)}`);
  }
}

/**
 * Parse arguments
 */
function getArgs() {
  return Object.fromEntries(
    $argument
      .split("&")
      .map((item) => {
        const [key, value] = item.split("=");
        return [key, value ? decodeURIComponent(value) : null];
      })
      .filter(([key]) => key) // filter out invalid arguments
  );
}

/**
 * Fetch user info
 */
function getUserInfo(url) {
  if (!url) {
    return Promise.reject("No valid subscription link provided");
  }

  const request = {
    headers: { "User-Agent": "Quantumult%20X" },
    url
  };

  return new Promise((resolve, reject) => {
    $httpClient.get(request, (err, resp) => {
      if (err) {
        return reject(`Network request error: ${err}`);
      }

      if (resp.status !== 200) {
        return reject(`Server returned a non-200 status code: ${resp.status}`);
      }

      const header = Object.keys(resp.headers).find(
        (key) => key.toLowerCase() === "subscription-userinfo"
      );

      if (header) {
        return resolve(resp.headers[header]);
      }

      reject("Response headers do not include usage info");
    });
  });
}

/**
 * Fetch and parse the data
 */
async function getDataInfo(url) {
  try {
    const data = await getUserInfo(url);

    // Extract data with a regex
    const matches = data.match(/\w+=[\d.eE+-]+/g);
    if (!matches || matches.length === 0) {
      throw new Error("Could not parse the returned data");
    }

    // Parse the key/value pairs
    return Object.fromEntries(
      matches.map((item) => {
        const [key, value] = item.split("=");
        return [key, Number(value)];
      })
    );
  } catch (error) {
    console.log(`Failed to fetch data: ${error}`);
    return null;
  }
}

/**
 * Compute the days remaining until reset
 */
function getRemainingDays(resetDay) {
  // Validate the reset day
  if (!resetDay || resetDay < 1 || resetDay > 31) return null;

  const now = new Date();
  const today = now.getDate();
  const currentYear = now.getFullYear();
  const currentMonth = now.getMonth();

  // Days in the current month
  const daysInThisMonth = new Date(currentYear, currentMonth + 1, 0).getDate();

  // Clamp the reset day to the last day of the month if it overflows
  const adjustedResetDay = Math.min(resetDay, daysInThisMonth);

  // If the reset day is still ahead this month
  if (adjustedResetDay > today) {
    return adjustedResetDay - today;
  }

  // If the reset day has passed, count the days to next month's reset day
  const daysInNextMonth = new Date(currentYear, currentMonth + 2, 0).getDate();
  const nextMonthResetDay = Math.min(resetDay, daysInNextMonth);

  return daysInThisMonth - today + nextMonthResetDay;
}

/**
 * Compute the days remaining until expiry
 */
function getExpireDaysLeft(expire) {
  if (!expire) return null;

  const now = new Date().getTime();
  let expireTime;

  // Handle a timestamp or a date string
  if (typeof expire === 'number' || /^[\d.]+$/.test(expire)) {
    // Ensure the timestamp is in milliseconds
    expireTime = parseInt(expire);
    if (expireTime < 1000000000000) {
      expireTime *= 1000; // convert seconds to milliseconds
    }
  } else {
    // Try to parse the date string
    expireTime = new Date(expire).getTime();
    if (isNaN(expireTime)) {
      console.log("Invalid expiry date format");
      return null;
    }
  }

  const daysLeft = Math.ceil((expireTime - now) / (1000 * 60 * 60 * 24));
  return daysLeft > 0 ? daysLeft : null;
}

/**
 * Convert bytes to a human-readable size
 */
function bytesToSize(bytes) {
  if (bytes === 0) return "0B";

  const units = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return (bytes / Math.pow(k, i)).toFixed(2) + " " + units[i];
}

/**
 * Format a time value
 */
function formatTime(time) {
  if (!time) return "Unknown date";

  // Handle a timestamp
  let timestamp = time;
  if (typeof time !== 'number' && /^[\d.]+$/.test(time)) {
    timestamp = parseInt(time);
  }

  // Ensure the timestamp is in milliseconds
  if (timestamp < 1000000000000) {
    timestamp *= 1000;
  }

  try {
    const date = new Date(timestamp);
    if (isNaN(date.getTime())) {
      // Try parsing it as a date string
      const stringDate = new Date(time);
      if (isNaN(stringDate.getTime())) {
        return "Invalid date";
      }
      date = stringDate;
    }

    const year = date.getFullYear();
    const month = date.getMonth() + 1;
    const day = date.getDate();

    return `${year}-${month}-${day}`;
  } catch (error) {
    console.log(`Date formatting error: ${error}`);
    return "Date parse error";
  }
}
