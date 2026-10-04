const { generateExcelReport } = require('./services/excelGenerator');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function test() {
    try {
        const scan = await prisma.scanHistory.findFirst({
            include: { project: true }
        });
        if (!scan) {
            console.log("No scans found in DB to test with.");
            process.exit(0);
        }
        console.log("Testing Excel generation for scan:", scan.id);
        const buffer = await generateExcelReport(scan, scan.project?.name || "Test");
        console.log("Excel generated successfully! Buffer length:", buffer.length);
        process.exit(0);
    } catch (err) {
        console.error("Excel generation FAILED:", err);
        process.exit(1);
    }
}

test();
