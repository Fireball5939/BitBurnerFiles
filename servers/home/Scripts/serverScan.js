/** @param {NS} ns */
// Declare variables

// Declare strings
let copyFile = ``;
let runFile = ``;

// Declare booleans
let hasSSH = false;
let hasFTP = false;
let hasSMTP = false;
let hasHTTP = false;
let hasSQL = false;

// Declare objects

// Declare numbers
let currentServer = 0;
let ramToUse = 100;

// Declare arrays
let serverList = ns.scan(`home`);
let scannedServers = [];
let serverClasses = [];

// Declare classes
class Server 
{
    constructor(ip, name, cores, root, ram, minSec, maxMon, pServ, hackReq) 
    {
        this.ip = ip;
        this.dnsName = name;
        this.cores = cores;
        this.hasRoot = root;
        this.maxRam = ram;
        this.minSec = minSec;
        this.maxMon = maxMon;
        this.pServ = pServ;
        this.hackReq = hackReq
    }

    inform(type, destination) 
    {
        if (destination = `terminal`) ns.tprint(`Information about this server is: ${type}`);
        else if (destination = `logs`) ns.print(`Information about this server is: ${type}`);
        else console.log(`Information about this server is: ${type}`);
    }
}

// Check to see if we have a given port buster
if (ns.fileExists(`BruteSSH.exe`, `home`)) hasSSH = true;
if (ns.fileExists(`FTPCrack.exe`, `home`)) hasFTP = true;
if (ns.fileExists(`relaySMTP.exe`, `home`)) hasSMTP = true;
if (ns.fileExists(`HTTPWorm.exe`, `home`)) hasHTTP = true;
if (ns.fileExists(`SQLInject.exe`, `home`)) hasSQL = true;

// If the -c or --copyfile argument is given then give a prompt for the player to give a file to copy
if (ns.args.includes(`-c`) || ns.args.includes(`--copyfile`)) copyFile = await ns.prompt(`What file are we copying?`, { type: `text` });

// If the --runfile argument is given then give a prompt for the player to give a file to run
if (ns.args.includes(`--runfile`)) {
    runFile = await ns.prompt(`What file are we running?`, { type: `text` });
    ramToUse = await ns.prompt(`How much ram do we use with this? Range: 0-100 (Percent value)`, { type: `text` });
}

// Iterate over every server we find, executing functions if they are given.
for (; currentServer < serverList.length; currentServer++) 
    {
    // Get the current server being scanned as an object
    const targetServer = ns.getServer(serverList[currentServer]);

    // Skip the server if it has already been scanned or is home
    if (scannedServers.includes(targetServer.hostname) || targetServer.hostname.includes(`home`)) continue;

    // Push this server to the list of scanned servers
    scannedServers.push(targetServer.hostname);

    // Create a buffer list of every server connected to this one
    const buffer = ns.scan(targetServer.hostname);

    // Filter out all servers that have already been scanned from the buffer list
    buffer.filter((server) => !server.includes(scannedServers));

    // Add the remaining servers to the server list
    serverList.push(...buffer);

    // Declare the class for this server
    const serverClass = new Server
    (
        targetServer.ip,
        targetServer.hostname,
        targetServer.cpucores,
        targetServer.hasAdminRights,
        targetServer.maxRam,
        targetServer.minimumSecurity,
        targetServer.isPuchased,
        targetServer.reqHackingLevel
    )

    // If --root is a given argument then gain root access on the server
    if (ns.args.includes(`--root`) && !targetServer.hasAdminRights) 
    {
        if (!targetServer.sshPortOpen && hasSSH) ns.brutessh(targetServer.hostname);
        if (!targetServer.ftpPortOpen && hasFTP) ns.ftpcrack(targetServer.hostname);
        if (!targetServer.smtpPortOpen && hasSMTP) ns.relaysmtp(targetServer.hostname);
        if (!targetServer.httpPortOpen && hasHTTP) ns.httpworm(targetServer.hostname);
        if (!targetServer.sqlPortOpen && hasSQL) ns.sqlinject(targetServer.hostname);
        try { ns.nuke(targetServer.hostname) } catch { }
    }

    // If -k or --killall is a given argument then kill all running scripts on the server
    if (ns.args.includes(`-k`) || ns.args.includes(`--killall`)) ns.killall(targetServer.hostname);

    // If -c or --copyfile is a given argument then copy a given file to the server
    if (ns.args.includes(`-c`) || ns.args.includes(`--copyfile`)) ns.scp(copyFile, targetServer.hostname);

    // If --runfile is a given argument then run a given file on the server IF it can be run
    if (ns.args.includes(`--runfile`) && ns.fileExists(runFile, targetServer.hostname) && (runFile.includes(`.js`) || runFile.includes(`.scripts`))) 
    {
        const threads = Math.floor((targetServer.maxRam - targetServer.ramUsed) * ramToUse / ns.getScriptRam(runFile, targetServer.hostname));
        ns.exec(runFile, targetServer.hostname, threads);
    }
}