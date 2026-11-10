#!/bin/bash

log_info "Creating admin user..."
cat > "$PROJECT_DIR/create-admin.js" << 'ADMINEOF'
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function createAdmin() {
  try {
    const username = process.env.ADMIN_USER;
    const password = process.env.ADMIN_PASSWORD;
    const hash = await bcrypt.hash(password, 12);
    await prisma.user.upsert({
      where: { username },
      update: { password: hash },
      create: {
        username,
        password: hash,
        role: 'admin',
      },
    });
    console.log('Admin user created/updated successfully');
  } catch (error) {
    console.error('Error creating admin user:', error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

createAdmin();
ADMINEOF

cd "$PROJECT_DIR" || log_error "Failed to enter project directory: $PROJECT_DIR"
ADMIN_USER="$ADMIN_USER" ADMIN_PASSWORD="$ADMIN_PASSWORD" node create-admin.js || log_error "Failed to create admin user"
rm -f "$PROJECT_DIR/create-admin.js"

log_info "Building Next.js app..."
export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=1536}"
npm run build