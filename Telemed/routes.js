const express = require('express');
const router = express.Router();
const connection = require('./db'); // Import the database connection
const bcrypt = require('bcryptjs'); // Import bcrypt

// Get all patients
router.get('/patients', (req, res) => {
    connection.query('SELECT * FROM Patients', (err, results) => {
        if (err) {
            return res.status(500).send('Error retrieving patients');
        }
        res.json(results);
    });
});

// Add a new patient (Registration)
router.post('/patients', (req, res) => {
    const { first_name, last_name, email, password, phone, date_of_birth, gender, address } = req.body;


    // Hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error during hashing:', err); // Debug hashing error
            return res.status(500).send('Error hashing password');
        }

        // Insert into the database
        connection.query(
            'INSERT INTO Patients (first_name, last_name, email, password_hash, phone, date_of_birth, gender, address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [first_name, last_name, email, hashedPassword, phone, date_of_birth, gender, address],
            (err) => {
                if (err) {
                    console.error('Error adding patient:', err); // Debug database error
                    return res.status(500).send('Error adding patient');
                }
                res.status(201).send('Patient added successfully');
            }
        );
    });
});

// Patient login
router.post('/login', (req, res) => {
    const { email, password } = req.body;

    // Check if the email exists
    connection.query('SELECT * FROM Patients WHERE email = ?', [email], (err, results) => {
        if (err) {
            return res.status(500).send('Error retrieving patient');
        }

        if (results.length === 0) {
            return res.status(404).send('Invalid email or password');
        }

        // Compare the provided password with the stored hashed password
        const patient = results[0];
        bcrypt.compare(password, patient.password_hash, (err, isMatch) => {
            if (err) {
                return res.status(500).send('Error during password comparison');
            }

            if (!isMatch) {
                return res.status(404).send('Invalid email or password');
            }

            // Successful login
            req.session.patientId = patient.id; // Store the patient ID in the session
            res.redirect('/dashboard.html');
        });
    });
});

// Get patient profile (view profile)
router.get('/profile', (req, res) => {
    const patientId = req.session.patientId; // Get patient ID from session
    if (!patientId) {
        return res.status(401).send('Unauthorized'); // Not logged in
    }

    // Query to fetch patient details
    connection.query('SELECT first_name, last_name, phone, date_of_birth, gender, address FROM Patients WHERE id = ?', [patientId], (err, results) => {
        if (err) {
            return res.status(500).send('Error retrieving patient profile');
        }
        res.json(results[0]); // Send back the patient profile
    });
});

// Update patient profile
router.put('/profile', (req, res) => {
    const patientId = req.session.patientId; // Get patient ID from session
    if (!patientId) {
        return res.status(401).send('Unauthorized'); // Not logged in
    }

    const { first_name, last_name, phone, date_of_birth, gender, address } = req.body;

    // Query to update patient details
    connection.query(
        'UPDATE Patients SET first_name = ?, last_name = ?, phone = ?, date_of_birth = ?, gender = ?, address = ? WHERE id = ?',
        [first_name, last_name, phone, date_of_birth, gender, address, patientId],
        (err) => {
            if (err) {
                return res.status(500).send('Error updating patient profile');
            }
            res.send('Profile updated successfully');
        }
    );
});

// Book an appointment
router.post('/appointments', (req, res) => {
    const { doctor_id, appointment_date, appointment_time } = req.body;
    const patientId = req.session.patientId;

    if (!patientId) {
        return res.status(401).send('Unauthorized'); // Not logged in
    }

    connection.query(
        'INSERT INTO Appointments (patient_id, doctor_id, appointment_date, appointment_time, status) VALUES (?, ?, ?, ?, ?)',
        [patientId, doctor_id, appointment_date, appointment_time, 'scheduled'],
        (err, result) => { // Capture result to get the inserted ID
            if (err) {
                return res.status(500).send('Error booking appointment');
            }
            const appointmentId = result.insertId; // Get the inserted ID
            res.status(201).json({ message: 'Appointment booked successfully', appointmentId }); // Send back ID
        }
    );
});

// Reschedule an appointment
router.put('/appointments/:id', (req, res) => {
    const appointmentId = req.params.id;
    const { appointment_date, appointment_time } = req.body;
    
    connection.query(
        'UPDATE Appointments SET appointment_date = ?, appointment_time = ? WHERE id = ?',
        [appointment_date, appointment_time, appointmentId],
        (err) => {
            if (err) {
                return res.status(500).send('Error rescheduling appointment');
            }
            res.send('Appointment rescheduled successfully');
        }
    );
});

// Cancel an appointment
router.delete('/appointments/:id', (req, res) => {
    const appointmentId = req.params.id;

    connection.query(
        'UPDATE Appointments SET status = "canceled" WHERE id = ?',
        [appointmentId],
        (err) => {
            if (err) {
                return res.status(500).send('Error canceling appointment');
            }
            res.send('Appointment canceled successfully');
        }
    );
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
router.get('/doctors', (req, res) => {
    connection.query('SELECT * FROM Doctors', (err, results) => {
        if (err) {
            return res.status(500).send('Error retrieving doctors');
        }
        res.json(results);
    });
});

// Add a new doctor
router.post('/register-doctor', async (req, res) => {
    const { first_name, last_name, specialization, email, phone, password } = req.body;

    try {
        // Hash the password
        const password_hash = await bcrypt.hash(password, 10);

        // SQL Query to insert data
        const sql = `
            INSERT INTO doctors (first_name, last_name, specialization, email, phone, password_hash, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, NOW());
        `;
        const values = [first_name, last_name, specialization, email, phone, password_hash];

        // Execute the query
        db.query(sql, values, (err, result) => {
            if (err) {
                console.error('Error inserting doctor:', err);
                return res.status(500).send('Registration failed. Try again later.');
            }
            res.send('Doctor registered successfully!');
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        res.status(500).send('An error occurred. Try again later.');
    }
});

// Get all appointments
router.get('/appointments', (req, res) => {
    connection.query('SELECT * FROM Appointments', (err, results) => {
        if (err) {
            return res.status(500).send('Error retrieving appointments');
        }
        res.json(results);
    });
});

// Admin Registration
router.post('/admin/register', (req, res) => {
    const { username, password } = req.body;

    // Check if the admin already exists
    connection.query('SELECT * FROM admin WHERE username = ?', [username], (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Database error' });
        }
        if (results.length > 0) {
            return res.status(400).json({ success: false, message: 'Username already taken' });
        }

        // Hash the password using bcrypt
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Error hashing password' });
            }

            // Insert new admin with hashed password
            connection.query(
                'INSERT INTO admin (username, password_hash, role) VALUES (?, ?, ?)',
                [username, hashedPassword, 'admin'],  // Assuming 'admin' as the default role, adjust if needed
                (err) => {
                    if (err) {
                        return res.status(500).json({ success: false, message: 'Registration failed' });
                    }
                    res.status(201).json({ success: true, message: 'Admin registered successfully' });
                }
            );
        });
    });
});



// Admin Login Route
router.post('/admin/login', (req, res) => {
    const { username, password } = req.body;

    // Check if the admin exists in the database
    connection.query('SELECT * FROM admin WHERE username = ?', [username], (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, message: 'Invalid username or password' });
        }

        const admin = results[0];

        // Compare the entered password with the hashed password in the database
        bcrypt.compare(password, admin.password_hash, (err, isMatch) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Error during password comparison' });
            }

            if (!isMatch) {
                return res.status(400).json({ success: false, message: 'Invalid username or password' });
            }

            // Successful login, create a session for the admin
            req.session.adminId = admin.id; // Store admin ID in session
            req.session.adminRole = admin.role; // Store admin role if needed

            res.json({ success: true, message: 'Login successful' });
        });
    });
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
        res.redirect('/login-admin.html');
    });
});


// Export the router
module.exports = router;