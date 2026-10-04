const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
    const schedules = await prisma.auditSchedule.findMany({
        include: { project: true }
    });
    console.log(JSON.stringify(schedules, null, 2));
}

main()
    .catch(e => console.error(e))
    .finally(async () => {
        await prisma.$disconnect();
    });
