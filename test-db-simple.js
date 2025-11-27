require('dotenv').config();
const { connectToDatabase } = require('../database/config/connection');
const Repository = require('../database/models/Repository');

async function testDatabase() {
  console.log('Testing simple database operations...\n');
  
  try {
    // Connect using the shared connection module
    await connectToDatabase();
    
    console.log('1. Finding repositories...');
    const repos = await Repository.find().limit(5);
    console.log(`   Found ${repos.length} repositories\n`);
    
    console.log('2. Creating a test repository...');
    const testRepo = await Repository.create({
      name: 'test-scanner-repo',
      full_name: 'local/test-scanner-repo',
      owner: 'local',
      url: '/test/path',
      html_url: '/test/path',
      language: 'JavaScript'
    });
    console.log(`   ✅ Created: ${testRepo.name}\n`);
    
    console.log('3. Finding the test repository...');
    const found = await Repository.findOne({ name: 'test-scanner-repo' });
    console.log(`   ✅ Found: ${found ? found.name : 'NOT FOUND'}\n`);
    
    console.log('4. Deleting test repository...');
    await Repository.deleteOne({ name: 'test-scanner-repo' });
    console.log('   ✅ Deleted\n');
    
    console.log('✅ All database operations work!');
    process.exit(0);
    
  } catch (error) {
    console.error('❌ Database test failed:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

testDatabase();

