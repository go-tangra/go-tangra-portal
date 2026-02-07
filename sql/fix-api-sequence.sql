-- Fix PostgreSQL sequence for sys_apis table
-- Run this if you see "duplicate key value violates unique constraint sys_apis_pkey" errors

-- Reset the sequence to the max ID + 1
SELECT setval(
    pg_get_serial_sequence('sys_apis', 'id'),
    COALESCE((SELECT MAX(id) FROM sys_apis), 0) + 1,
    false
);

-- Verify the sequence value
SELECT currval(pg_get_serial_sequence('sys_apis', 'id')) AS current_sequence_value,
       (SELECT MAX(id) FROM sys_apis) AS max_id_in_table;
