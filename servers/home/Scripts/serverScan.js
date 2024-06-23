/** @param {NS} iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll */
export async function main(iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll) {
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
let serverList = iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.scan(`home`);
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
        if (destination = `terminal`) iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.tprint(`Information about this server is: ${type}`);
        else if (destination = `logs`) iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.print(`Information about this server is: ${type}`);
        else console.log(`Information about this server is: ${type}`);
    }
}

// Check to see if we have a given port buster
if (iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.fileExists(`BruteSSH.exe`, `home`)) hasSSH = true;
if (iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.fileExists(`FTPCrack.exe`, `home`)) hasFTP = true;
if (iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.fileExists(`relaySMTP.exe`, `home`)) hasSMTP = true;
if (iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.fileExists(`HTTPWorm.exe`, `home`)) hasHTTP = true;
if (iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.fileExists(`SQLInject.exe`, `home`)) hasSQL = true;

// If the -c or --copyfile argument is given then give a prompt for the player to give a file to copy
if (iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.args.includes(`-c`) || iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.args.includes(`--copyfile`)) copyFile = await iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.prompt(`What file are we copying?`, { type: `text` });

// If the --runfile argument is given then give a prompt for the player to give a file to run
if (iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.args.includes(`--runfile`)) {
    runFile = await iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.prompt(`What file are we running?`, { type: `text` });
    ramToUse = await iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.prompt(`How much ram do we use with this? Range: 0-100 (Percent value)`, { type: `text` });
}

// Iterate over every server we find, executing functions if they are given.
for (; currentServer < serverList.length; currentServer++) 
    {
    // Get the current server being scanned as an object
    const targetServer = iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.getServer(serverList[currentServer]);

    // Skip the server if it has already been scanned or is home
    if (scannedServers.includes(targetServer.hostname) || targetServer.hostname.includes(`home`)) continue;

    // Push this server to the list of scanned servers
    scannedServers.push(targetServer.hostname);

    // Create a buffer list of every server connected to this one
    const buffer = iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.scan(targetServer.hostname);

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
    if (iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.args.includes(`--root`) && !targetServer.hasAdminRights) 
    {
        if (!targetServer.sshPortOpen && hasSSH) iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.brutessh(targetServer.hostname);
        if (!targetServer.ftpPortOpen && hasFTP) iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.ftpcrack(targetServer.hostname);
        if (!targetServer.smtpPortOpen && hasSMTP) iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.relaysmtp(targetServer.hostname);
        if (!targetServer.httpPortOpen && hasHTTP) iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.httpworm(targetServer.hostname);
        if (!targetServer.sqlPortOpen && hasSQL) iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.sqlinject(targetServer.hostname);
        try { iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.nuke(targetServer.hostname) } catch { }
    }

    // If -k or --killall is a given argument then kill all running scripts on the server
    if (iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.args.includes(`-k`) || iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.args.includes(`--killall`)) iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.killall(targetServer.hostname);

    // If -c or --copyfile is a given argument then copy a given file to the server
    if (iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.args.includes(`-c`) || iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.args.includes(`--copyfile`)) iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.scp(copyFile, targetServer.hostname);

    // If --runfile is a given argument then run a given file on the server IF it can be run
    if (iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.args.includes(`--runfile`) && iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.fileExists(runFile, targetServer.hostname) && (runFile.includes(`.js`) || runFile.includes(`.scripts`))) 
    {
        const threads = Math.floor((targetServer.maxRam - targetServer.ramUsed) * ramToUse / iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.getScriptRam(runFile, targetServer.hostname));
        iJustReallyWantToPissOffXsinxWithThisCodeForNoReasonAtAll.exec(runFile, targetServer.hostname, threads);
    }
}
}