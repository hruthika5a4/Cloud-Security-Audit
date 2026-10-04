const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function cleanupOrphans() {
    console.log('🔍 Starting database integrity check...');
    try {
        const schedules = await prisma.auditSchedule.findMany();
        console.log(`Checking ${schedules.length} schedules...`);
        
        let removedCount = 0;
        for (const schedule of schedules) {
            const user = await prisma.user.findUnique({
                where: { id: schedule.userId }
            });
            
            if (!user) {
                console.log(`⚠️  Orphan found: Schedule ${schedule.id} references non-existent user ${schedule.userId}. Deleting...`);
                await prisma.auditSchedule.delete({
                    where: { id: schedule.id }
                });
                removedCount++;
            }
        }
        
        console.log(`✅ Cleanup complete. Removed ${removedCount} orphan schedules.`);
    } catch (err) {
        console.error('❌ Error during cleanup:', err);
    } finally {
        await prisma.$disconnect();
    }
}

cleanupOrphans();
