const express = require('express');
const router = express.Router();
const connection = require('./db'); // Import the database connection
const bcrypt = require('bcryptjs'); // Import bcrypt

// Get all patients
router.get('/patients', async (req, res) => {
    try {
        const [results] = await connection.query('SELECT * FROM Patients');
        res.json(results);
    } catch (err) {
        res.status(500).send('Error retrieving patients');
    }
});


// Add a new patient (Registration)
router.post('/patients', async (req, res) => {
    const { first_name, last_name, email, password, phone, date_of_birth, gender, address } = req.body;

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert into the database
        await connection.query(
            'INSERT INTO Patients (first_name, last_name, email, password_hash, phone, date_of_birth, gender, address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [first_name, last_name, email, hashedPassword, phone, date_of_birth, gender, address]
        );

        res.status(201).send('Patient added successfully');
    } catch (err) {
        console.error('Error during registration:', err); // Debug error
        res.status(500).send('Error adding patient');
    }
});


// Patient login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if the email exists
        const [results] = await connection.query('SELECT * FROM Patients WHERE email = ?', [email]);

        if (results.length === 0) {
            return res.status(404).send('Invalid email or password');
        }

        // Compare the provided password with the stored hashed password
        const patient = results[0];
        const isMatch = await bcrypt.compare(password, patient.password_hash);

        if (!isMatch) {
            return res.status(404).send('Invalid email or password');
        }

        // Successful login
        req.session.patientId = patient.id; // Store the patient ID in the session
        res.redirect('/dashboard.html');
    } catch (err) {
        console.error('Error during login:', err); // Debug error
        res.status(500).send('Error during login');
    }
});


// Get patient profile (view profile)
router.get('/profile', async (req, res) => {
    const patientId = req.session.patientId; // Get patient ID from session
    if (!patientId) {
        return res.status(401).send('Unauthorized'); // Not logged in
    }

    try {
        // Query to fetch patient details
        const [results] = await connection.query('SELECT first_name, last_name, phone, date_of_birth, gender, address FROM Patients WHERE id = ?', [patientId]);

        if (results.length === 0) {
            return res.status(404).send('Patient not found');
        }

        res.json(results[0]); // Send back the patient profile
    } catch (err) {
        console.error('Error retrieving patient profile:', err); // Debug error
        res.status(500).send('Error retrieving patient profile');
    }
});


// Update patient profile
router.put('/profile', async (req, res) => {
    const patientId = req.session.patientId; // Get patient ID from session
    if (!patientId) {
        return res.status(401).send('Unauthorized'); // Not logged in
    }

    const { first_name, last_name, phone, date_of_birth, gender, address } = req.body;

    try {
        // Query to update patient details
        await connection.query(
            'UPDATE Patients SET first_name = ?, last_name = ?, phone = ?, date_of_birth = ?, gender = ?, address = ? WHERE id = ?',
            [first_name, last_name, phone, date_of_birth, gender, address, patientId]
        );

        res.send('Profile updated successfully');
    } catch (err) {
        console.error('Error updating patient profile:', err); // Debug error
        res.status(500).send('Error updating patient profile');
    }
});


// Fetch logged-in patient's appointments
router.get('/appointments/mine', async (req, res) => {
    if (!req.session.patientId) {
        return res.status(401).json({ error: 'Unauthorized. Please log in.' });
    }

    try {
        const [appointments] = await connection.query(
            `SELECT 
                a.id, 
                CONCAT(d.first_name, ' ', d.last_name) AS doctor_name,
                CONCAT(s.day_range, ' (', s.start_time, ' - ', s.end_time, ')') AS schedule,
                a.status
            FROM appointments a
            JOIN doctors d ON a.doctor_id = d.id
            JOIN schedules s ON a.schedule_id = s.id
            WHERE a.patient_id = ?
            ORDER BY a.created_at DESC`,
            [req.session.patientId]
        );

        res.status(200).json({ appointments });
    } catch (error) {
        console.error('Error fetching appointments:', error);
        res.status(500).json({ error: 'Database error' });
    }
});


// Fetch all doctors
router.get('/appointments/doctors', async (req, res) => {
    try {
        const [doctors] = await connection.query(
            'SELECT id, first_name, last_name, specialization FROM doctors'
        );
        res.status(200).json({ doctors });
    } catch (error) {
        console.error('Error fetching doctors:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

// Fetch schedules for a doctor
router.get('/appointments/schedules/:doctorId', async (req, res) => {
    const { doctorId } = req.params;
    try {
        const [schedules] = await connection.query(
            'SELECT id, day_range, start_time, end_time FROM schedules WHERE doctor_id = ?',
            [doctorId]
        );
        res.status(200).json({ schedules });
    } catch (error) {
        console.error('Error fetching schedules:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

// Book an appointment
router.post('/appointments/book', async (req, res) => {
    const { doctor_id, schedule_id } = req.body;

    if (!req.session.patientId) {
        return res.status(401).json({ error: 'Unauthorized. Please log in.' });
    }

    try {
        await connection.query(
            'INSERT INTO appointments (patient_id, doctor_id, schedule_id, status) VALUES (?, ?, ?, ?)',
            [req.session.patientId, doctor_id, schedule_id, 'Pending']
        );
        res.status(201).json({ message: 'Appointment booked successfully.' });
    } catch (error) {
        console.error('Error booking appointment:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

// Cancel an appointment
router.post('/appointments/cancel', async (req, res) => {
    const { appointment_id } = req.body;

    if (!req.session.patientId) {
        return res.status(401).json({ error: 'Unauthorized. Please log in.' });
    }

    try {
        // Verify the appointment belongs to the logged-in patient
        const [result] = await connection.query(
            'SELECT id FROM appointments WHERE id = ? AND patient_id = ?',
            [appointment_id, req.session.patientId]
        );

        if (result.length === 0) {
            return res.status(404).json({ error: 'Appointment not found or not authorized to cancel.' });
        }

        // Update appointment status to 'Cancelled'
        await connection.query(
            'UPDATE appointments SET status = ? WHERE id = ?',
            ['Cancelled', appointment_id]
        );

        res.status(200).json({ message: 'Appointment cancelled successfully.' });
    } catch (error) {
        console.error('Error cancelling appointment:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

// Logout route
router.get('/logout', (req, res) => {
    // Destroy the session
    req.session.destroy((err) => {
        if (err) {
            console.error('Error during logout:', err); // Log any error that happens during session destruction
            return res.status(500).send('Error during logout');
        }

        // Redirect to login page after successful logout
        res.redirect('/login.html');
    });
});

// Get all doctors
router.get('/doctors', async (req, res) => {
    try {
        // Query to get all doctors
        const [results] = await connection.query('SELECT * FROM Doctors');
        res.json(results);
    } catch (err) {
        console.error('Error retrieving doctors:', err); // Log any error
        res.status(500).send('Error retrieving doctors');
    }
});


// Doctor Registration
router.post('/doctor/register', async (req, res) => {
    const { first_name, last_name, email, password, phone, specialization } = req.body;

    try {
        // Check if the doctor already exists
        const [existingDoctors] = await connection.query(
            'SELECT * FROM doctors WHERE email = ?',
            [email]
        );

        if (existingDoctors.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash the password
        const passwordHash = await bcrypt.hash(password, 10);

        // Insert new doctor into the database
        await connection.query(
            'INSERT INTO doctors (first_name, last_name, email, password_hash, phone, specialization, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())',
            [first_name, last_name, email, passwordHash, phone, specialization]
        );

        res.status(201).json({ message: 'Doctor registered successfully' });
    } catch (error) {
        console.error('Error during doctor registration:', error);
        res.status(500).json({ error: 'Unexpected error occurred' });
    }
});

// Doctor Login
router.post('/doctor/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if the doctor exists
        const [doctors] = await connection.query('SELECT * FROM doctors WHERE email = ?', [email]);

        if (doctors.length === 0) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const doctor = doctors[0];

        // Compare the password with the stored hash
        const isMatch = await bcrypt.compare(password, doctor.password_hash);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        // Set session data
        req.session.doctorId = doctor.id;
        res.status(200).json({ message: 'Login successful' });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Unexpected error occurred' });
    }
});

// Add Doctor Schedule with Day Range
router.post('/doctor/schedule', async (req, res) => {
    if (!req.session.doctorId) {
        return res.status(401).json({ error: 'Unauthorized. Please log in as a doctor.' });
    }

    const { day_range, start_time, end_time } = req.body;

    try {
        // Insert schedule into the database
        const [result] = await connection.query(
            'INSERT INTO schedules (doctor_id, day_range, start_time, end_time) VALUES (?, ?, ?, ?)',
            [req.session.doctorId, day_range, start_time, end_time]
        );

        res.status(201).json({ message: 'Schedule added successfully' });
    } catch (error) {
        console.error('Error during schedule insertion:', error);
        res.status(500).json({ error: 'Failed to add schedule' });
    }
});


// Doctor Dashboard
router.get('/doctor/dashboard', async (req, res) => {
    if (!req.session.doctorId) {
        return res.status(401).json({ error: 'Unauthorized. Please log in as a doctor.' });
    }

    try {
        // Fetch doctor profile
        const [doctorResults] = await connection.query(
            'SELECT first_name, last_name, email, phone, specialization FROM doctors WHERE id = ?',
            [req.session.doctorId]
        );

        if (doctorResults.length === 0) {
            return res.status(404).json({ error: 'Doctor not found' });
        }

        const doctor = doctorResults[0];

        // Fetch doctor schedule
        const [scheduleResults] = await connection.query(
            'SELECT id, day_range, start_time, end_time FROM schedules WHERE doctor_id = ?',
            [req.session.doctorId]
        );

        res.status(200).json({ doctor, schedules: scheduleResults });
    } catch (error) {
        console.error('Error during doctor dashboard:', error);
        res.status(500).json({ error: 'Unexpected error occurred' });
    }
});

// Route to view pending appointments for a specific doctor
router.get('/doctor/appointments', async (req, res) => {
    const doctorId = req.session.doctorId;

    // SQL query to get pending appointments for the doctor
    const query = `
        SELECT a.id, a.status, p.first_name, p.last_name, p.email
        FROM appointments a
        JOIN patients p ON a.patient_id = p.id
        WHERE a.doctor_id = ?
    `;

    try {
        // Use the promise-based query method with the pool
        const [results] = await connection.query(query, [doctorId]);

        res.json(results); // Send appointments data as JSON
    } catch (err) {
        // Handle any errors that occur during the database query
        return res.status(500).send('Error fetching appointments');
    }
});

// Route to confirm an appointment
router.post('/doctor/appointments/confirm/:appointmentId', async (req, res) => {
    const appointmentId = req.params.appointmentId;

    // SQL query to update the appointment status to 'Confirmed'
    const query = 'UPDATE appointments SET status = ? WHERE id = ?';

    try {
        // Use the promise-based query method with the pool
        const [result] = await connection.query(query, ['Confirmed', appointmentId]);

        // If no rows were affected, the appointment might not exist
        if (result.affectedRows === 0) {
            return res.status(404).send('Appointment not found');
        }

        // Redirect back to the appointments page
        res.redirect('/doctor_appointment.html');
    } catch (err) {
        // Handle any errors that occur during the database query
        return res.status(500).send('Error confirming appointment');
    }
});

// Route to mark an appointment as completed
router.post('/doctor/appointments/complete/:appointmentId', async (req, res) => {
    const appointmentId = req.params.appointmentId;

    // SQL query to update the appointment status to 'Completed'
    const query = 'UPDATE appointments SET status = ? WHERE id = ?';

    try {
        // Use the promise-based query method with the pool
        const [result] = await connection.query(query, ['Completed', appointmentId]);

        // If no rows were affected, the appointment might not exist
        if (result.affectedRows === 0) {
            return res.status(404).send('Appointment not found');
        }

        // Redirect back to the appointments page
        res.redirect('/doctor_appointment.html');
    } catch (err) {
        // Handle any errors that occur during the database query
        return res.status(500).send('Error completing appointment');
    }
});

// Logout route
router.get('/doctor-logout', (req, res) => {
    // Destroy the session
    req.session.destroy((err) => {
        if (err) {
            console.error('Error during logout:', err); // Log any error that happens during session destruction
            return res.status(500).send('Error during logout');
        }

        // Redirect to login page after successful logout
        res.redirect('/doctor_login.html');
    });
});

// Get all appointments
router.get('/appointments', async (req, res) => {
    try {
        // Query to get all appointments
        const [results] = await connection.query('SELECT * FROM Appointments');
        res.json(results);
    } catch (err) {
        console.error('Error retrieving appointments:', err); // Log any error
        res.status(500).send('Error retrieving appointments');
    }
});

// Admin Registration
router.post('/admin/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Check if the admin already exists
        const [results] = await connection.query('SELECT * FROM admin WHERE username = ?', [username]);
        if (results.length > 0) {
            return res.status(400).json({ success: false, message: 'Username already taken' });
        }

        // Hash the password using bcrypt
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new admin with hashed password
        await connection.query(
            'INSERT INTO admin (username, password_hash, role) VALUES (?, ?, ?)',
            [username, hashedPassword, 'admin'] // Assuming 'admin' as the default role
        );

        res.status(201).json({ success: true, message: 'Admin registered successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Registration failed' });
    }
});

// Admin Login Route
router.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Check if the admin exists in the database
        const [results] = await connection.query('SELECT * FROM admin WHERE username = ?', [username]);

        if (results.length === 0) {
            return res.status(404).json({ success: false, message: 'Invalid username or password' });
        }

        const admin = results[0];

        // Compare the entered password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, admin.password_hash);

        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Invalid username or password' });
        }

        // Successful login, create a session for the admin
        req.session.adminId = admin.id; // Store admin ID in session

        res.json({ success: true, message: 'Login successful' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Login failed' });
    }
});

// // Admin Dashboard Data
// router.get('/admin/dashboard-data', async (req, res) => {
//     try {
//         // Fetch stats from the database
//         const [[{ totalPatients }]] = await connection.query('SELECT COUNT(*) AS totalPatients FROM patients');
//         const [[{ totalDoctors }]] = await connection.query('SELECT COUNT(*) AS totalDoctors FROM doctors');
//         const [[{ appointmentsToday }]] = await connection.query(`
//             SELECT COUNT(*) AS appointmentsToday 
//             FROM appointments 
//             WHERE DATE(created_at) = CURDATE()
//         `);

//         // Fetch analytics data (e.g., appointments per day)
//         const [analytics] = await connection.query(`
//             SELECT DAYNAME(created_at) AS day, COUNT(*) AS total
//             FROM appointments
//             WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
//             GROUP BY DAYNAME(created_at)
//         `);

//         // Format analytics data
//         const labels = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
//         const data = labels.map(day => {
//             const record = analytics.find(a => a.day === day);
//             return record ? record.total : 0;
//         });

//         // Send response
//         res.json({
//             success: true,
//             stats: {
//                 totalPatients,
//                 totalDoctors,
//                 appointmentsToday,
//             },
//             analytics: {
//                 labels,
//                 data,
//             },
//         });
//     } catch (err) {
//         console.error('Error fetching dashboard data:', err);
//         res.status(500).json({ success: false, message: 'Failed to fetch dashboard data' });
//     }
// });
router.get('/admin/dashboard-data', async (req, res) => {
    try {
        // Ensure admin is logged in (optional middleware logic can be applied)
        if (!req.session.adminId) {
            return res.status(403).json({ success: false, message: 'Unauthorized' });
        }

        // Fetch metrics
        const [totalPatients] = await connection.query('SELECT COUNT(*) AS count FROM patients');
        const [totalDoctors] = await connection.query('SELECT COUNT(*) AS count FROM doctors');
        const [appointmentStats] = await connection.query(`
            SELECT 
                SUM(status = 'Pending') AS pending,
                SUM(status = 'Confirmed') AS confirmed,
                SUM(status = 'Completed') AS completed
            FROM appointments
        `);

        // Fetch tables data
        const [patients] = await connection.query(`
            SELECT 
                CONCAT(first_name, ' ', last_name) AS name, 
                email, 
                phone, 
                DATE_FORMAT(created_at, '%Y-%m-%d') AS registration_date 
            FROM patients
        `);

        const [doctors] = await connection.query(`
            SELECT 
                CONCAT(first_name, ' ', last_name) AS name, 
                specialization, 
                email, 
                phone 
            FROM doctors
        `);

        const [appointments] = await connection.query(`
            SELECT 
                (SELECT CONCAT(first_name, ' ', last_name) FROM patients WHERE patients.id = appointments.patient_id) AS patient_name,
                (SELECT CONCAT(first_name, ' ', last_name) FROM doctors WHERE doctors.id = appointments.doctor_id) AS doctor_name,
                status,
                DATE_FORMAT(schedule_id, '%Y-%m-%d %H:%i') AS scheduled_date
            FROM appointments
        `);

        // Fetch analytics data
        const [appointmentsOverTime] = await connection.query(`
            SELECT 
                DATE(created_at) AS date, 
                COUNT(*) AS count 
            FROM appointments 
            GROUP BY DATE(created_at) 
            ORDER BY date ASC
        `);

        const analytics = {
            labels: appointmentsOverTime.map(row => row.date),
            data: appointmentsOverTime.map(row => row.count),
        };

        // Send response
        res.json({
            success: true,
            metrics: {
                totalPatients: totalPatients[0].count,
                totalDoctors: totalDoctors[0].count,
                pendingAppointments: appointmentStats[0].pending || 0,
                confirmedAppointments: appointmentStats[0].confirmed || 0,
                completedAppointments: appointmentStats[0].completed || 0,
            },
            patients,
            doctors,
            appointments,
            analytics,
        });
    } catch (err) {
        console.error('Error fetching dashboard data:', err);
        res.status(500).json({ success: false, message: 'Failed to fetch dashboard data' });
    }
});


// Admin patients route with search functionality
router.get('/adpatients', (req, res) => {

    const { search } = req.query;
    let query = 'SELECT id, first_name, last_name, email, phone FROM patients'; // Ensure you select the right fields
    const queryParams = [];

    // Check if there's a search term
    if (search) {
        query += ' WHERE first_name LIKE ? OR last_name LIKE ? OR email LIKE ?';
        queryParams.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    connection.query(query, queryParams, (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results);
    });
});

// Admin Logout route
router.get('/adminlogout', (req, res) => {
    // Destroy the session
    req.session.destroy((err) => {
        if (err) {
            console.error('Error during logout:', err); // Log any error that happens during session destruction
            return res.status(500).send('Error during logout');
        }

        // Redirect to login page after successful logout
        res.redirect('/admin_login.html');
    });
});


// Export the router
module.exports = router;