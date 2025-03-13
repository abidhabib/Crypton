import nodemailer from 'nodemailer';
import express from 'express';
import cors from 'cors';
import mysql from 'mysql2'; // Use mysql2
import bcrypt from 'bcrypt';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import multer from 'multer';
import path, { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path'
import dotenv from 'dotenv';
import cron from 'node-cron';
dotenv.config();
const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);


app.use('/uploads', express.static(join(__dirname, 'uploads')));
app.use(bodyParser.json());
app.use(cors({
    origin: 'http://localhost:5173',
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'],  // Added 'PUT' here

    credentials: true,

}));


app.use(cookieParser());
app.use(express.json());
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 86400000 }  // secure should be true in production

}));
const PORT = 8082;
const con = mysql.createConnection({
    host: '127.0.0.1',
    user: 'root',
    password: 'Pakistan@2k17',
    database: 'apps_up',
});



con.connect(function (err) {
    if (err) {
        console.error('Error in connection:', err);
    } else {
        console.log('Connected');
    }
}
);


app.get('/', (req, res) => {
    if (req.session.email) {
        return res.json({ valid: true, Email: req.session.email });
    }
    else {
        return res.json({ valid: false, Status: "!valid" });
    }
})


const delayBetweenBatches = 2000; // 2 seconds
const batchSize = 1000;  // Number of users to update in each batch

const updateBatch = (offset = 0) => {
    // Query to get users to be updated
    const selectQuery = `
        SELECT id
        FROM users 
        WHERE approved = 1 
        AND today_team > 0
        AND today_team_update >= CURDATE() - INTERVAL 1 DAY
        LIMIT ${batchSize} OFFSET ${offset};
    `;

    con.query(selectQuery, (err, users) => {
        if (err) {
            console.error('Error fetching users:', err);
            return;
        }

        if (users.length === 0) {
            console.log('No more users to update. All batches processed.');
            return;
        }

        // Extract user IDs to update
        const userIds = users.map(user => user.id).join(',');

        // Update query for the selected users
        const updateQuery = `
            UPDATE users 
            SET week_team = week_team + today_team, 
                today_team = 0
            WHERE id IN (${userIds});
        `;

        con.query(updateQuery, (err, result) => {
            if (err) {
                console.error('Error updating users:', err);
            } else {
                console.log(`Updated batch: ${offset} - ${offset + batchSize}, Affected Rows: ${result.affectedRows}`);
                offset += batchSize;
                // Delay before the next batch update
                setTimeout(() => updateBatch(offset), delayBetweenBatches);
            }
        });
    });
};

cron.schedule('0 0 * * *', () => {
    console.log('Starting daily update for today_team and week_team at', new Date().toISOString());
    updateBatch();  // Start the batch update process from offset 0
});


app.post('/login', (req, res) => {
    const sql = "SELECT * FROM users WHERE email = ? AND password = ?";
    con.query(sql, [req.body.email, req.body.password], (err, result) => {
        if (err) return res.json({ Status: "Error", Error: err });

        if (result.length > 0) {
            req.session.userId = result[0].id;
            req.session.email = result[0].email;
            return res.json({
                Status: "Success",
                Email: req.session.email,
                PaymentOk: result[0].payment_ok,
                id: result[0].id,
                approved: result[0].approved
            });
        } else {
            return res.json({ Status: "Error", Error: "Invalid Email/Password" });
        }
    });
});

app.post('/register', (req, res) => {
    try {
        const { ref } = req.query;
        const user = { ...req.body };
        delete user.confirmPassword;

        const checkEmailSql = "SELECT * FROM users WHERE email = ?";
        con.query(checkEmailSql, [user.email], (err, existingUsers) => {
            if (err) {
                return res.json({ status: 'error', error: 'An error occurred while checking the email' });
            }

            if (existingUsers.length > 0) {
                return res.json({ status: 'error', error: 'Email already registered' });
            }

            const registerUser = () => {
                const sql = "INSERT INTO users SET ?";
                con.query(sql, user, (err, result) => {
                    if (err) {
                        console.log('Failed to register user:', err);

                        return res.json({ status: 'error', error: 'Failed to register user' });
                    }

                    // Update the refer_by field for the user registering
                    if (ref) {
                        user.refer_by = ref; // Add the refer_by field
                        const referralSql = "INSERT INTO referrals (referrer_id, referred_id) VALUES (?, ?)";
                        con.query(referralSql, [ref, result.insertId], (err, referralResult) => {
                            if (err) {
                                console.error('Failed to record referral:', err);
                                return res.json({ status: 'error', error: 'Failed to record referral' });
                            }
                            const updateReferBySql = "UPDATE users SET refer_by = ? WHERE id = ?";
                            con.query(updateReferBySql, [ref, result.insertId], (err, updateResult) => {
                                if (err) {
                                    return res.json({ status: 'error', error: 'Failed to update refer_by' });
                                }
                                return res.json({ status: 'success', message: 'User registered successfully with referral', userId: result.insertId });
                            });
                        });
                    } else {
                        return res.json({ status: 'success', message: 'User registered successfully', userId: result.insertId });
                    }
                });
            };

            if (ref) {
                const checkReferralSql = "SELECT * FROM users WHERE id = ?";
                con.query(checkReferralSql, [ref], (err, referralUsers) => {
                    if (err) {
                        return res.json({ status: 'error', error: 'Failed to check referral ID' });
                    }

                    if (referralUsers.length === 0) {
                        return res.json({ status: 'error', error: 'Invalid referral ID' });
                    }

                    registerUser();
                });
            } else {
                registerUser();
            }
        });
    } catch (error) {
        return res.json({ status: 'error', error: 'An unexpected error occurred' });
    }
});



async function registerUser(userData, res) {
    // This function will register the user in the database
    const hashedPassword = await bcrypt.hash(userData.password, 10); // Make sure to hash the password before storing it

    const user = {
        ...userData,
        password: hashedPassword
    };

    const sql = "INSERT INTO users SET ?";
    con.query(sql, user, (err, result) => {
        if (err) {
            res.json({ status: 'error', error: 'Failed to register user' });
            return;
        }

        res.json({ status: 'success', userId: result.insertId });
    });
}
app.get('/get-fee', (req, res) => {
    const sql = 'SELECT joining_fee FROM joining_fee WHERE id = ?';


    const accountId = 1;


    con.query(sql, [accountId], (err, result) => {
        if (err) {
            console.error('Error fetching fee:', err);
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the fee.' });
        }

        if (result.length > 0) {
            const feeValue = result[0].joining_fee;
            res.status(200).json({ success: true, fee: feeValue });
        } else {
            res.status(404).json({ success: false, message: 'No fee found for the given account ID.' });
        }
    });
});

app.post('/sendPassword', (req, res) => {
    const userEmail = req.body.userEmail;

    const sql = 'SELECT password FROM users WHERE email = ?';
    con.query(sql, [userEmail], (err, results) => {
        if (err) throw err;

        if (results.length > 0) {
            const userPassword = results[0].password;

            // Send password to the user's email
            const transporter = nodemailer.createTransport({
                host: 'smtp.titan.email',
                port: 587,
                secure: false, // TLS
                auth: {
                    user: 'recovery@maps-earning.com',
                    pass: 'Pakistan@2k17'
                }
            });

            const mailOptions = {
                from: 'recovery@maps-earning.com',
                to: userEmail,
                subject: 'Your Password Recovery',
                html: `
          <html>
            <body>
              <div style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                <h2 style="color: #333;">Password Recovery</h2>
                <p style="color: #555;">Hello!</p>
                <p style="color: #555;">We have received a request for password recovery.</p>
                <p style="color: #555;">Your password is: <strong style="color: #992cd3; font-weight: bold; font-size: 18px;">${userPassword}</strong>.</p>
                <p style="color: #555;">Please ensure to keep your password secure and do not share it with anyone.</p>
                <p style="color: #555;">If you didn't request this change, please contact support immediately.</p>
                <p style="color: #555;">Thank you!</p>
              </div>
            </body>
          </html>
        `
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.log(error);
                    res.status(500).send('Error sending email');
                } else {
                    console.log('Email sent: ' + info.response);
                    res.status(200).send('Password sent to your email');
                }
            });
        } else {
            res.status(404).send('User not found');
        }
    });
});

app.post('/payment', (req, res) => {
    const { trx_id, sender_name, sender_number, id } = req.body;
    const payment_ok = 1;
    const rejected = 0;

    // Check if the trx_id already exists in the users table
    const checkQuery = 'SELECT COUNT(*) AS count FROM users WHERE trx_id = ?';
    con.query(checkQuery, [trx_id], (checkErr, checkResults) => {
        if (checkErr) {
            return res.status(500).json({ status: 'error', error: 'Database error' });
        }

        // Inside the '/payment' route
        if (checkResults[0].count > 0) {
            // The trx_id already exists; return an error response
            return res.status(400).json({ status: 'error', error: 'Transaction ID already in use' });
        }


        // The trx_id doesn't exist; update the user's payment data
        const sql = 'UPDATE users SET trx_id = ?, sender_name = ?, sender_number = ?, payment_ok = ?, rejected = ? WHERE id = ?';

        con.query(sql, [trx_id, sender_name, sender_number, payment_ok, rejected, id], (err, result) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to update payment data' });
            }

            res.json({ status: 'success' });
        });
    });
});

app.get('/getUserData', (req, res) => {
    if (!req.session.email) {
        return res.json({ Status: 'Error', Error: 'User not logged in' });
    }

    const sql = "SELECT * FROM users WHERE email = ?";
    con.query(sql, [req.session.email], (err, result) => {
        if (err) {
            return res.json({ Status: 'Error', Error: 'Failed to fetch user data' });
        }

        if (result.length > 0) {
            return res.json({ Status: 'Success', Data: result[0] });
        } else {
            return res.json({ Status: 'Error', Error: 'User not found' });
        }
    });
});
app.get('/getAllAdmins', (req, res) => {
    const sql = "SELECT * FROM admins";
    con.query(sql, (err, result) => {
        if (err) {
            return res.json({ Status: 'Error', Error: 'Failed to fetch admins data' });
        }

        if (result.length > 0) {
            return res.json({ Status: 'Success', Data: result });
        } else {
            return res.json({ Status: 'Error', Error: 'No admins found' });
        }
    });
});


app.post('/changePassword', (req, res) => {
    const { username, oldPassword, newPassword } = req.body;

    const sql = "SELECT password FROM admins WHERE username = ?";

    con.query(sql, [username], (err, result) => {
        if (err || result.length === 0) {
            return res.json({ message: 'Username not found' });
        }

        const storedPassword = result[0].password;

        if (storedPassword !== oldPassword) {
            return res.json({ message: 'Old password is incorrect' });
        }

        const updateSql = "UPDATE admins SET password = ? WHERE username = ?";

        con.query(updateSql, [newPassword, username], (updateErr, updateResult) => {
            if (updateErr) {
                return res.json({ message: 'Failed to update password' });
            }

            return res.json({ message: 'Password updated successfully' });
        });
    });
});

app.get('/fetchClickedProducts', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ status: 'error', error: 'User not authenticated' });
    }

    const userId = req.session.userId;
    const today = new Date().toISOString().split('T')[0];

    const getClickedProductsSql = `
             SELECT p.*, upc.last_clicked
        FROM products p
        LEFT JOIN user_product_clicks upc 
        ON p.id = upc.product_id AND upc.user_id = ?
    `;

    con.query(getClickedProductsSql, [userId], (err, productResults) => {
        if (err) {
            console.error('Fetch clicked products query error:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch clicked products' });
        }

        const products = productResults.map(product => ({
            ...product,
            canClick: !product.last_clicked || new Date(product.last_clicked).toISOString().split('T')[0] !== today
        }));

        const productCount = products.length;

        if (productCount > 0) {
            const updateWalletSql = `
              UPDATE users
SET 
    today_wallet = CASE
        WHEN COALESCE(last_wallet_update, '') <> ? THEN (backend_wallet * 0.1 / ?)
        ELSE today_wallet
    END,
    backend_wallet = CASE
        WHEN COALESCE(last_wallet_update, '') <> ? THEN backend_wallet - backend_wallet * 0.1
        ELSE backend_wallet
    END,
    last_wallet_update = CASE
        WHEN COALESCE(last_wallet_update, '') <> ? THEN ?
        ELSE last_wallet_update
    END
WHERE id = ? AND (COALESCE(last_wallet_update, '') <> ?)
            `;

            con.query(updateWalletSql, [today, productCount, today, today, today, userId, today], (err) => {
                if (err) {
                    console.error('Update wallet query error:', err);
                    return res.status(500).json({ status: 'error', error: 'Failed to update wallet' });
                }

                const getUserDataSql = 'SELECT today_wallet FROM users WHERE id = ?';
                con.query(getUserDataSql, [userId], (err, userResults) => {
                    if (err) {
                        console.error('Fetch user wallet query error:', err);
                        return res.status(500).json({ status: 'error', error: 'Failed to fetch user data' });
                    }

                    const today_wallet = userResults[0]?.today_wallet || 0;
                    res.json({
                        status: 'success',
                        products,
                        today_wallet
                    });
                });
            });
        } else {
            res.json({
                status: 'success',
                products: [],
                today_wallet: 0
            });
        }
    });
});

app.post('/updateBalance', (req, res) => {
    const { productId, reward } = req.body;

    if (!req.session.userId) {
        return res.json({ Status: 'Error', Error: 'User not logged in' });
    }

    const checkLastClickedSql = 'SELECT last_clicked FROM user_product_clicks WHERE user_id = ? AND product_id = ?';
    con.query(checkLastClickedSql, [req.session.userId, productId], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to check the last clicked time' });
        }

        const currentTime = new Date();

        if (result.length > 0) {
            const lastClicked = new Date(result[0].last_clicked);
            const timeDifference = currentTime - lastClicked;

            if (timeDifference < 12 * 60 * 60 * 1000) {
                return res.json({ status: 'error', error: 'You have completed your task' });
            }
        }

        const updateBalanceSql = `UPDATE users SET balance = balance + ? WHERE id = ?`;
        con.query(updateBalanceSql, [reward, req.session.userId], (err, updateResult) => {
            if (err) {
                console.log('Error updating balance:', err);

                return res.status(500).json({ status: 'error', error: 'Failed to update the balance and backend wallet' });
            }

            const updateLastClickedSql = `
                INSERT INTO user_product_clicks (user_id, product_id, last_clicked) 
                VALUES (?, ?, ?) 
                ON DUPLICATE KEY UPDATE last_clicked = VALUES(last_clicked)
            `;

            con.query(updateLastClickedSql, [req.session.userId, productId, currentTime], (err, clickResult) => {
                if (err) {
                    return res.status(500).json({ status: 'error', error: 'Failed to update the last clicked time' });
                }

                return res.json({ status: 'success', message: 'Balance and backend wallet updated successfully' });
            });
        });
    });
});




app.put('/updateProfile', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ status: 'error', error: 'User not logged in' });
    }

    // Destructure the fields you want to update from the request body
    const { name, city } = req.body;

    if (!name || !city) {
        return res.status(400).json({ status: 'error', error: 'Name and city are required' });
    }

    // SQL query to update the user's data
    const sql = 'UPDATE users SET name = ?, city = ? WHERE id = ?';

    con.query(sql, [name, city, req.session.userId], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to update profile' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', error: 'User not found' });
        }

        // If you want to return the updated data in the response, you can make another query to get the updated data
        con.query('SELECT * FROM users WHERE id = ?', [req.session.userId], (err, updatedUserData) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to fetch updated user data' });
            }

            // Return the updated user data in the response
            res.json({ status: 'success', updatedUser: updatedUserData[0] });
        });
    });
});
app.post('/logout', (req, res) => {
    if (req.session) {
        // Destroy session if it exists
        req.session.destroy(err => {
            if (err) {
                return res.json({ Status: 'Error', Error: 'Failed to logout' });
            }

            return res.json({ Status: 'Success', Message: 'Logged out successfully' });
        });
    } else {
        return res.json({ Status: 'Error', Error: 'No session to logout' });
    }
});

app.get('/referrals', async (req, res) => {
    const referrerId = req.query.referrerId;

    if (!referrerId) {
        return res.status(400).json({ status: 'error', error: 'Referrer ID is required' });
    }

    // First, fetch all referrals for the given referrerId
    const sqlReferrals = `
        SELECT * FROM referrals 
        WHERE referrer_id = ? 
    `;

    con.query(sqlReferrals, [referrerId], async (err, referrals) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch referrals' });
        }

        if (referrals.length > 0) {
            // If there are referrals, then check each referred_id in the users table
            const referredIds = referrals.map(referral => referral.referred_id);
            const sqlUsers = `
                SELECT COUNT(*) as approvedCount FROM users 
                WHERE id IN (?) 
                AND approved = 1;
            `;

            con.query(sqlUsers, [referredIds], (err, results) => {
                if (err) {
                    return res.status(500).json({ status: 'error', error: 'Failed to fetch users' });
                }

                return res.json({ status: 'success', approvedReferralsCount: results[0].approvedCount });
            });
        } else {
            return res.status(404).json({ status: 'error', error: 'No approved referrals found for this referrer ID' });
        }
    });
});



app.post('/admin-login', (req, res) => {
    const sentloginUserName = req.body.LoginUserName
    const sentLoginPassword = req.body.LoginPassword

    const sql = 'SELECT * FROM admins WHERE username = ? && password = ?'
    const Values = [sentloginUserName, sentLoginPassword]

    con.query(sql, Values, (err, results) => {
        if (err) {
            res.send({ error: err })
        }
        if (results.length > 0) {
            res.send(results)
        }
        else {
            res.send({ message: `Credentials Don't match!` })
        }
    })
})

app.get('/users-by-email', (req, res) => {
    const email = req.query.email || ''; // Extract email from query parameters
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 10; // Adjust the default value as needed
    const sortKey = req.query.sortKey || 'id'; // Default sort key
    const sortDirection = req.query.sortDirection || 'asc'; // Default sort direction

    let sql = `SELECT id,balance,team, name,email,phoneNumber,trx_id,total_withdrawal,CurrTeam,refer_by,password FROM  users
    WHERE 
        approved = 1
        AND payment_ok = 1`;
    if (email) {
        sql += ` AND (email LIKE '%${email}%' OR id = '${email}' OR trx_id LIKE '%${email}%')`;
    } else {
        sql += ` AND (CurrTeam >= 3 OR team >= 5)`;
    }


    const countSql = `SELECT COUNT(*) AS totalCount FROM users WHERE approved = 1 AND payment_ok = 1 ${email ? `AND email LIKE '%${email}%'` : ''}`;

    console.log('Count SQL Query:', countSql);

    con.query(countSql, (countErr, countResult) => {
        if (countErr) {
            console.error('Count Query Error:', countErr); // Log count query error
            return res.status(500).json({ success: false, message: 'An error occurred while fetching total count.' });
        }

        const totalCount = countResult[0].totalCount;
        console.log('Total Count:', totalCount);

        // Apply sorting based on the requested column and direction
        sql += ` ORDER BY ${sortKey} ${sortDirection}`;
        console.log('Final SQL Query:', sql);

        con.query(sql, (err, result) => {
            if (err) {
                console.error('Main Query Error:', err); // Log main query error
                return res.status(500).json({ success: false, message: 'An error occurred while fetching users by email.' });
            }

            res.status(200).json({
                success: true,
                users: result,
                totalCount: totalCount,
                currentPage: page,
                totalPages: Math.ceil(totalCount / perPage)
            });
        });
    });
});


app.get('/approved-users', (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 10; // Adjust the default value as needed
    const searchTerm = req.query.searchTerm || ''; // Extract searchTerm from query parameters
    const sortKey = req.query.sortKey || 'id'; // Default sort key
    const sortDirection = req.query.sortDirection || 'asc'; // Default sort direction


    let sql = `SELECT id,balance,team,  name,email,phoneNumber,trx_id,total_withdrawal,CurrTeam,refer_by,password FROM  users
    WHERE 
        approved = 1
        AND payment_ok = 1`;

    if (searchTerm) {
        sql += ` AND (name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%' OR id = '${searchTerm}')`;
    } else {
        sql += ` AND (CurrTeam >= 3 OR team >= 5)`;
    }

    console.log('SQL Query:', sql);

    const countSql = `SELECT COUNT(*) AS totalCount FROM users WHERE approved = 1 AND payment_ok = 1 ${searchTerm ? `AND (name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%' OR id = '${searchTerm}')` : ''}`;

    console.log('Count SQL Query:', countSql);

    con.query(countSql, (countErr, countResult) => {
        if (countErr) {
            console.error('Count Query Error:', countErr); // Log count query error
            return res.status(500).json({ success: false, message: 'An error occurred while fetching total count.' });
        }

        const totalCount = countResult[0].totalCount;
        console.log('Total Count:', totalCount);

        // Apply sorting based on the requested column and direction
        sql += ` ORDER BY ${sortKey} ${sortDirection}`;
        console.log('Final SQL Query:', sql);

        con.query(sql, (err, result) => {
            if (err) {
                console.error('Main Query Error:', err); // Log main query error
                return res.status(500).json({ success: false, message: 'An error occurred while fetching approved users.' });
            }

            res.status(200).json({
                success: true,
                approvedUsers: result,
                totalCount: totalCount,
                currentPage: page,
                totalPages: Math.ceil(totalCount / perPage)
            });
        });
    });
});



app.get('/todayApproved', (req, res) => {
    const sql = `SELECT * FROM users WHERE approved = 1 AND DATE(approved_at) = CURDATE()`;

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', approvedUsers: result });
        } else {
            return res.status(404).json({ status: 'error', error: 'No approved users found' });
        }
    });
});


app.put('/rejectUserCurrMin/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;

        if (!userId) {
            return res.status(400).json({ status: 'error', message: 'User ID is required' });
        }

        // Fetch the refer_by user's ID
        const referByIdQuery = 'SELECT refer_by FROM users WHERE id = ?';
        const referByIdResult = await new Promise((resolve, reject) => {
            con.query(referByIdQuery, [userId], (err, result) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(result);
                }
            });
        });

        if (referByIdResult.length === 0 || !referByIdResult[0].refer_by) {
            return res.status(404).json({ status: 'error', message: 'Refer_by user not found' });
        }

        const referById = referByIdResult[0].refer_by;

        // Update the current user
        const updateCurrentUserQuery = `
            UPDATE users 
            SET 
                rejected = 1, 
                payment_ok = 0,
                approved = 0,
                rejected_at = CURRENT_TIMESTAMP 
            WHERE id = ? AND rejected = 0`;

        await new Promise((resolve, reject) => {
            con.query(updateCurrentUserQuery, [userId], (err, result) => {
                if (err) {
                    console.error('Error updating current user:', err);
                    reject(err);
                } else {
                    console.log('Update current user result:', result);
                    resolve(result);
                }
            });
        });

        // Update CurrTeam of the refer_by user
        const updateReferByUserQuery = `
            UPDATE users 
            SET CurrTeam = GREATEST(CurrTeam - 1, 0)
            WHERE id = ?`;

        await new Promise((resolve, reject) => {
            con.query(updateReferByUserQuery, [referById], (err, result) => {
                if (err) {
                    console.error('Error updating refer_by user:', err);
                    reject(err);
                } else {
                    console.log('Update refer_by user result:', result);
                    resolve(result);
                }
            });
        });

        res.json({ status: 'success', message: 'User rejected successfully', data: {} });
    } catch (error) {
        console.error('Error rejecting user:', error);
        return res.status(500).json({ status: 'error', error: 'Failed to reject user', details: error.message });
    }
});

app.put('/rejectUser/:userId', (req, res) => {
    const userId = req.params.userId;

    if (!userId) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }

    const sql = `
        UPDATE users 
        SET 
            rejected = 1, 
            payment_ok = 0,
            approved = 0,

                        rejected_at = CURRENT_TIMESTAMP 
        WHERE id = ? AND rejected = 0`;

    con.query(sql, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to reject user' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found or already rejected' });
        }

        res.json({ status: 'success', message: 'User rejected successfully' });
    });
});


app.get('/rejectedUsers', (req, res) => {
    const sql = 'SELECT * FROM users WHERE rejected = 1 ';

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {
            return res.json({ status: 'success', approvedUsers: result });
        } else {

        }
    });
});


app.get('/EasypaisaUsers', (req, res) => {
    const sql = 'SELECT * FROM users WHERE approved = 0 && payment_ok = 1';

    con.query(sql, (err, result) => {
        if (err) {

            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
        }

        if (result.length > 0) {

            return res.json({ status: 'success', approvedUsers: result });
        } else {

            return res.status(404).json({ status: 'error', error: 'No approved users found' });
        }
    });
});

const fetchApprovedUserNames = (referByUserId) => {
    return new Promise((resolve, reject) => {
        const fetchNamesQuery = 'SELECT id, name ,phoneNumber,backend_wallet FROM users WHERE refer_by = ? AND approved = 1';
        con.query(fetchNamesQuery, [referByUserId], (err, results) => {
            if (err) {
                reject(err);
            } else {
                resolve(results);

            }
        });
    });
};


app.get('/approvedUserNames/:referByUserId', async (req, res) => {
    const { referByUserId } = req.params;

    try {
        const users = await fetchApprovedUserNames(referByUserId);
        res.json({ status: 'success', users });
    } catch (error) {
        console.error('Error fetching approved users:', error);
        res.status(500).json({ status: 'error', error: 'Failed to fetch approved users' });
    }
});

app.post('/withdraw', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ status: 'error', error: 'User not logged in' });
    }

    const userId = req.session.userId;
    const { amount, accountName, accountNumber, bankName, totalWithdrawn, team } = req.body;

    if (!amount || !userId || !accountName || !accountNumber || !bankName) {
        return res.status(400).json({ status: 'error', error: 'All fields are required' });
    }

    const checkRequestSql = `
        SELECT * FROM withdrawal_requests
        WHERE user_id = ? AND approved = 'pending' AND reject = 0
    `;

    con.query(checkRequestSql, [userId], (err, results) => {
        if (err) {
            console.log(err);
            return res.status(500).json({ status: 'error', error: 'Failed to check for existing requests', details: err.message });
        }

        if (results.length > 0) {
            return res.status(400).json({ status: 'error', error: 'You already have a pending withdrawal request' });
        }

        const getUserSql = `
            SELECT level, balance, team FROM users WHERE id = ?
        `;

        con.query(getUserSql, [userId], (err, userResults) => {
            if (err) {
                return res.status(500).json({ status: 'error', error: 'Failed to fetch user details', details: err.message });
            }

            if (userResults.length === 0) {
                return res.status(500).json({ status: 'error', error: 'User not found' });
            }

            const userLevel = userResults[0].level;
            const userBalance = userResults[0].balance;
            const userTeam = userResults[0].team;

            if (userTeam <= 0) {
                return res.status(400).json({ status: 'error', error: 'You cannot withdraw this amount' });
            }

            const checkLimitsSql = `
                SELECT * FROM withdraw_limit
                WHERE level = ? AND ? >= min AND ? <= max
            `;

            con.query(checkLimitsSql, [userLevel, amount, amount], (err, limitResults) => {
                if (err) {
                    return res.status(500).json({ status: 'error', error: 'Failed to check withdrawal limits', details: err.message });
                }

                if (limitResults.length === 0) {
                    return res.status(400).json({ status: 'error', error: 'You cannot withdraw this amount' });
                }

                const getExchangeFeeSql = `
                    SELECT fee FROM exchange_fee WHERE id = 1
                `;

                con.query(getExchangeFeeSql, (err, feeResults) => {
                    if (err) {
                        return res.status(500).json({ status: 'error', error: 'Failed to fetch exchange fee', details: err.message });
                    }

                    if (feeResults.length === 0) {
                        return res.status(500).json({ status: 'error', error: 'Exchange fee not found' });
                    }

                    const feePercentage = feeResults[0].fee;
                    const fee = (amount * feePercentage) / 100;
                    const amountAfterFee = amount - fee;

                    if (amountAfterFee <= 0) {
                        return res.status(400).json({ status: 'error', error: 'Amount after fee must be greater than zero' });
                    }

                    if (userBalance < amount) {
                        return res.status(400).json({ status: 'error', error: 'Insufficient balance' });
                    }

                    con.beginTransaction(err => {
                        if (err) {
                            return res.status(500).json({ status: 'error', error: 'Failed to start transaction' });
                        }

                        const withdrawSql = `
                            INSERT INTO withdrawal_requests (user_id, amount, account_name, account_number, bank_name, total_withdrawn, team, request_date, approved, fee)
                            VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), 'pending', ?)
                        `;

                        con.query(withdrawSql, [userId, amountAfterFee, accountName, accountNumber, bankName, totalWithdrawn, team, fee], (err, withdrawResult) => {
                            if (err) {
                                return con.rollback(() => {
                                    console.log(err);
                                    return res.status(500).json({ status: 'error', error: 'Failed to make withdrawal', details: err.message });
                                });
                            }

                            con.commit(err => {
                                if (err) {
                                    return con.rollback(() => {
                                        return res.status(500).json({ status: 'error', error: 'Failed to commit transaction', details: err.message });
                                    });
                                }
                                return res.json({ status: 'success', message: 'Withdrawal request submitted successfully' });
                            });
                        });
                    });
                });
            });
        });
    });
});

app.post('/collectBonus', (req, res) => {
    const userId = req.session.userId;
    console.log('User ID:', userId);

    const sql = `SELECT level_updated, balance FROM users WHERE id = ?`;

    con.query(sql, [userId], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: 'error', message: 'Failed to retrieve user data' });
        }

        if (result.length === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        const user = result[0];

        if (user.level_updated === 1) {
            // User is eligible for the bonus, increment the balance by 100
            const updateBalanceQuery = `UPDATE users SET balance = balance + 100, level_updated = 0 WHERE id = ?`;
            const bonusAmount = 100;

            con.query(updateBalanceQuery, [userId], (err, updateResult) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ status: 'error', message: 'Failed to update balance' });
                }

                // Log the bonus collection in the bonus_history table
                const logBonusQuery = `INSERT INTO bonus_history (user_id, bonus_amount) VALUES (?, ?)`;

                con.query(logBonusQuery, [userId, bonusAmount], (err, logResult) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).json({ status: 'error', message: 'Failed to log bonus collection' });
                    }

                    res.json({ status: 'success', message: 'Bonus collected and logged successfully!' });
                });
            });
        } else {
            // User's level_updated is not 1
            return res.status(403).json({ status: 'error', message: 'You are not eligible to collect the bonus' });
        }
    });
});
app.get('/bonusHistory', (req, res) => {
    const userId = req.session.userId;
    console.log('User ID:', userId);

    if (!userId) {
        return res.status(401).json({ status: 'error', message: 'User not authenticated' });
    }

    const sql = `
        SELECT bonus_amount, collected_at 
        FROM bonus_history 
        WHERE user_id = ? 
        ORDER BY collected_at DESC
    `;

    con.query(sql, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching bonus history:', err);
            return res.status(500).json({ status: 'error', message: 'Failed to retrieve bonus history' });
        }

        if (results.length === 0) {
            return res.json([]);
        }

        res.json(results);
    });
});




app.put('/updateUser', (req, res) => {
    if (!req.body.id) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }

    const { id, name, email, password, balance, CurrTeam, trx_id, total_withdrawal } = req.body;

    const sql = `
        UPDATE users 
        SET 
            name = ?, 
            email = ?, 
            password = ?,
            balance = ?, 
            CurrTeam = ?,
            trx_id = ?, 
            total_withdrawal = ? 
        WHERE id = ?`;

    con.query(sql, [name, email, password, balance, CurrTeam, trx_id, total_withdrawal, id], (err, result) => {
        if (err) {
            console.error(err); // Log the error to the console here
            return res.status(500).json({ status: 'error', error: 'Failed to update user' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        res.json({ status: 'success', message: 'User updated successfully' });
    });
});




app.put('/approveUser/:userId', (req, res) => {
    const userId = req.params.userId;

    if (!userId) {
        return res.status(400).json({ status: 'error', message: 'User ID is required' });
    }

    const updateUsersQuery = `
    UPDATE users 
    SET 
        approved = 1, 
        payment_ok = 1,
        rejected = 0,
        approved_at = CURRENT_TIMESTAMP,
        backend_wallet = backend_wallet + (
            SELECT joining_fee * (SELECT initial_percent FROM initial_fee WHERE id = 1) / 100
            FROM joining_fee
            WHERE id = 1
        ) 
    WHERE id = ?`;

    const getReferrerIdQuery = `
        SELECT refer_by
        FROM users
        WHERE id = ?`;

    const getJoiningFeeQuery = `
        SELECT joining_fee
        FROM joining_fee
        WHERE id = 1`;

    const incrementCurrTeamForReferrerQuery = `
      UPDATE users AS u1
        JOIN users AS u2 ON u1.id = u2.id
        JOIN levels AS l ON u2.team + 1 >= l.min_team AND u2.team + 1 <= l.max_team
        SET u1.team = u2.team + 1,
            u1.level = l.level,
            u1.balance = IF(u1.level <> l.level, u1.balance + 40, u1.balance) 
        WHERE u1.id = ?;
    `;

    const incrementTodayTeamForReferrerQuery = `
        UPDATE users
        SET today_team = today_team + 1
        WHERE id = ?;
    `;

    const updateBalancesAndWalletQuery = `
        UPDATE users AS u
        JOIN commission AS c1 ON u.id = c1.person
        LEFT JOIN users AS r ON u.refer_by = r.id
        LEFT JOIN commission AS c2 ON r.id = c2.person
        JOIN joining_fee AS j ON j.id = 1
        SET 
            u.backend_wallet = u.backend_wallet + COALESCE((c2.indirect_bonus * (j.joining_fee / 100)), 0)
        WHERE u.id = ?`;

    const insertIntoWinstukBuyHistoryQuery = `
        INSERT INTO indirect_bonus
 (user_id, amount, value, created_at, created_date)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_DATE)`;

    const IncrementsChain = (referrerId, depth) => {
        if (depth < 7) {
            updateBalancesAndWallet(referrerId, depth);
        } else {
            console.log('Reached maximum referral depth');
        }
    };

    const updateBalancesAndWallet = (userId, depth) => {
        if (depth >= 7) {
            return;
        }

        con.query(updateBalancesAndWalletQuery, [userId], (err, updateResult) => {
            if (err) {
                console.error('Error updating balances and wallet:', err);
                return;
            }

            con.query(getReferrerIdQuery, [userId], (err, referrerResult) => {
                if (err) {
                    console.error('Error fetching referrer ID:', err);
                    return;
                }

                const referrerId = referrerResult[0]?.refer_by;

                if (referrerId) {
                    const commissionQuery = `
                        SELECT direct_bonus, indirect_bonus
                        FROM commission
                        WHERE id = ?`;
                    con.query(commissionQuery, [depth], (err, commissionResult) => {
                        if (err) {
                            console.error('Error fetching commission data:', err);
                            return;
                        }

                        const directBonus = commissionResult[0]?.direct_bonus || 0;
                        const indirectBonus = commissionResult[0]?.indirect_bonus || 0;

                        con.query(getJoiningFeeQuery, (err, feeResult) => {
                            if (err) {
                                console.error('Error fetching joining fee:', err);
                                return;
                            }

                            const joiningFee = feeResult[0]?.joining_fee || 0;

                            const directBonusPercentage = (directBonus * (joiningFee / 100));
                            const indirectBonusPercentage = (indirectBonus * (joiningFee / 100));

                            const updateBalancesQuery = `
                                  UPDATE users
                                SET balance = balance + ?,
                                    backend_wallet = backend_wallet + ?
                                WHERE id = ?`;
                            console.log(directBonusPercentage, indirectBonusPercentage, referrerId);

                            con.query(updateBalancesQuery, [directBonusPercentage, indirectBonusPercentage, referrerId], (err, updateBalancesResult) => {
                                if (err) {
                                    console.error('Error updating referrer balances:', err);
                                    return;
                                }

                                con.query(insertIntoWinstukBuyHistoryQuery, [referrerId, directBonusPercentage, directBonusPercentage], (err, insertResult) => {
                                    if (err) {
                                        console.error('Error inserting into balances:', err);
                                        return;
                                    }

                                    IncrementsChain(referrerId, depth + 1);
                                });
                            });
                        });
                    });

                } else {
                    console.log('Reached top of referral hierarchy');
                }
            });

        });
    };

    con.beginTransaction((err) => {
        if (err) {
            console.error('Transaction start failed:', err);
            return res.status(500).json({ status: 'error', error: 'Transaction start failed' });
        }

        con.query(updateUsersQuery, [userId], (err, userResult) => {
            if (err) {
                console.error('Error updating users:', err);
                return con.rollback(() => {
                    res.status(500).json({ status: 'error', error: 'Failed to update user' });
                });
            }

            if (userResult.affectedRows === 0) {
                console.error('User not found or already approved');
                return con.rollback(() => {
                    res.status(404).json({ status: 'error', message: 'User not found or already approved' });
                });
            }

            updateBalancesAndWallet(userId, 0);

            con.query(getReferrerIdQuery, [userId], (err, referrerResult) => {
                if (err) {
                    console.error('Error fetching referrer ID:', err);
                    return con.rollback(() => {
                        res.status(500).json({ status: 'error', error: 'Failed to fetch referrer ID' });
                    });
                }

                const referrerId = referrerResult[0]?.refer_by;

                if (referrerId) {
                    con.query(incrementCurrTeamForReferrerQuery, [referrerId], (err, incrementResult) => {
                        if (err) {
                            console.error('Error incrementing CurrTeam for referring user:', err);
                            return con.rollback(() => {
                                res.status(500).json({ status: 'error', error: 'Failed to increment CurrTeam for referring user' });
                            });
                        }

                        con.query(incrementTodayTeamForReferrerQuery, [referrerId], (err, todayTeamResult) => {
                            if (err) {
                                console.error('Error incrementing today_team for referring user:', err);
                                return con.rollback(() => {
                                    res.status(500).json({ status: 'error', error: 'Failed to increment today_team for referring user' });
                                });
                            }

                            con.commit((err) => {
                                if (err) {
                                    console.error('Error committing transaction:', err);
                                    return con.rollback(() => {
                                        res.status(500).json({ status: 'error', error: 'Failed to commit transaction' });
                                    });
                                }

                                res.status(200).json({ status: 'success', message: 'User approved and balances updated' });
                            });
                        });
                    });

                } else {
                    console.log('Reached top of referral hierarchy');
                }
            });
        });
    });
});

app.get('/withdrawal-requests', (req, res) => {
    const userId = req.session.userId;

    if (!userId) {
        return res.approved(401).json({ approved: 'error', error: 'User not logged in' });
    }

    const sql = 'SELECT user_id,request_date,reject, amount ,bank_name, approved FROM withdrawal_requests WHERE user_id = ? ORDER BY request_date DESC LIMIT 30'; // Adjust your SQL query accordingly

    con.query(sql, [userId], (err, results) => {
        if (err) {
            return res.approved(500).json({ approved: 'error', error: 'Failed to fetch withdrawal requests' });
        }

        const formattedResults = results.map(request => ({
            id: request.user_id,
            date: request.request_date,
            amount: request.amount,
            bank_name: request.bank_name,
            approved: request.approved,
            reject: request.reject

        }));
        console.log(formattedResults);
        res.json(formattedResults);
    });
});

app.get('/all-withdrawal-requests', (req, res) => {
    const sql = 'SELECT * FROM withdrawal_requests WHERE approved = "pending" && reject = "0"';
    con.query(sql, (error, results) => {
        if (error) {
            res.status(500).json({ error: 'Internal Server Error' });
            return;
        }
        console.log(results);
        const mappedResults = results.map(item => ({
            id: item.id,
            user_id: item.user_id,
            amount: item.amount,
            account_name: item.account_name,
            bank_name: item.bank_name,
            account_number: item.account_number,
            approved: item.approved === 1,
            team: item.team,
            total_withdrawn: item.total_withdrawn
        }));
        console.log(mappedResults);
        res.json(mappedResults);
    });
});

app.post('/approve-withdrawal', async (req, res) => {
    const { userId, requestId, amount } = req.body;

    if (!userId || !requestId || !amount) {
        return res.status(400).json({ error: 'User ID, request ID, and amount are required' });
    }

    const updateWithdrawalRequestsSql = `
        UPDATE withdrawal_requests 
        SET approved = 'approved', reject = 0, approved_time = CURRENT_TIMESTAMP 
        WHERE id = ? AND user_id = ? AND approved = 'pending'`;

    const updateUserBalanceAndTotalWithdrawalSql = `
        UPDATE users
        SET balance = 0,
            total_withdrawal = total_withdrawal + ?
        WHERE id = ?`;

    con.beginTransaction(error => {
        if (error) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        con.query(updateWithdrawalRequestsSql, [requestId, userId], (error, results) => {
            if (error) {
                return con.rollback(() => {
                    res.status(500).json({ error: 'Internal Server Error' });
                });
            }

            if (results.affectedRows === 0) {
                return res.status(400).json({ error: 'Could not find the withdrawal request or it is already approved' });
            }

            con.query(updateUserBalanceAndTotalWithdrawalSql, [amount, userId], (error, results) => {
                if (error) {
                    return con.rollback(() => {
                        res.status(500).json({ error: 'Internal Server Error' });
                    });
                }

                con.commit(error => {
                    if (error) {
                        return con.rollback(() => {
                            res.status(500).json({ status: 'error', error: 'Failed to commit transaction' });
                        });
                    }

                    res.json({ message: 'Withdrawal request approved, balance and total withdrawal updated successfully!' });
                });
            });
        });
    });
});




app.post('/reject-withdrawal', async (req, res) => {
    const { requestId, userId } = req.body;

    if (!requestId || !userId) {
        return res.status(400).json({ error: 'Request ID and User ID are required' });
    }

    const updateWithdrawalRequestsSql = `
        UPDATE withdrawal_requests 
        SET reject=1, approved='pending', reject_at=CURRENT_TIMESTAMP 
        WHERE id=? AND user_id=? ;
    `;

    try {
        con.query(updateWithdrawalRequestsSql, [requestId, userId], (err, result) => {
            if (err) {
                console.error('Error executing query', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (result.affectedRows > 0) {
                // Successful update
                return res.json({ message: 'Withdrawal request rejected successfully!' });
            } else {
                // No rows updated, meaning the provided IDs were not found
                return res.status(404).json({ error: 'No matching withdrawal request found' });
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.get('/withdrawalRequestsApproved', (req, res) => {
    const sql = 'SELECT * FROM withdrawal_requests WHERE approved = "approved" && reject = 0';

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved withdrawal requests' });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: 'error', message: 'No approved withdrawal requests found' });
        }

        res.json({ status: 'success', data: results });
    });
});
app.get('/withdrawalRequestsRejected', (req, res) => {
    const sql = 'SELECT * FROM withdrawal_requests WHERE approved = "pending" && reject = 1';

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch approved withdrawal requests' });
        }

        if (results.length === 0) {
            return res.status(404).json({ status: 'error', message: 'No approved withdrawal requests found' });
        }

        res.json({ status: 'success', data: results });
    });
});
app.get('/products', (req, res) => {
    const sql = 'SELECT * FROM products';

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the products.' });
        }

        res.status(200).json({ success: true, data: results });
    });
});


app.post('/products', (req, res) => {
    const { description, link, reward, imgLink } = req.body;
    console.log(req.body);
    if (!description || !link || !imgLink) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    const product = { description, link, imgLink };
    const sql = 'INSERT INTO products SET ?';

    con.query(sql, product, (err, result) => {
        if (err) {
            console.log(err);

            return res.status(500).json({ success: false, message: 'An error occurred while adding the product.' }

            );

        }
        res.status(201).json({ success: true, message: 'Product added successfully.' });
    });
});

app.delete('/products/:id', (req, res) => {
    const id = req.params.id;

    if (!id) {
        return res.status(400).json({ success: false, message: 'ID is required.' });
    }

    const sql = 'DELETE FROM products WHERE id = ?';
    con.query(sql, [id], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while deleting the product.' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Product not found.' });
        }

        res.status(200).json({ success: true, message: 'Product deleted successfully.' });
    });
});

app.put('/products/:id', (req, res) => {
    const id = req.params.id;
    const { description, link, imgLink } = req.body;
    console.log(req.body);
    if (!description || !link || !imgLink) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    const sql = 'UPDATE products SET description = ?, link = ?,  imgLink = ? WHERE id = ?';

    con.query(sql, [description, link, imgLink, id], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while updating the product.' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Product not found.' });
        }

        res.status(200).json({ success: true, message: 'Product updated successfully.' });
    });
});


app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    let sql = `SELECT * FROM users WHERE id = ${con.escape(userId)}`;
    con.query(sql, (err, result) => {
        if (err) {
            res.status(500).send(err);
            return;
        }

        if (result.length === 0) {
            res.status(404).send({ message: 'User not found' });
            return;
        }

        res.send(result[0]);
    });
});





app.get('/get-accounts', (req, res) => {
    const sql = 'SELECT * FROM accounts';

    con.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching accounts.' });
        }

        res.status(200).json({ success: true, accounts: results });
    });
});
app.get('/fetchLevelsData', (req, res) => {
    const sql = 'SELECT * FROM levels';

    con.query(sql, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch commission data' });
        }

        res.json({ status: 'success', data: result });
    });
});
app.get('/fetchLimitsData', (req, res) => {
    const sql = 'SELECT * FROM withdraw_limit';

    con.query(sql, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch commission data' });
        }

        res.json({ status: 'success', data: result });
    });
});


app.get('/fetchCommissionData', (req, res) => {
    const sql = 'SELECT * FROM commission';

    con.query(sql, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: 'error', error: 'Failed to fetch commission data' });
        }

        res.json({ status: 'success', data: result });
    });
});


app.put('/updateCommissionData', (req, res) => {
    const { id, direct_bonus, indirect_bonus } = req.body;

    if (!direct_bonus || !indirect_bonus) {
        return res.status(400).json({ status: 'error', message: 'Direct Bonus and Indirect Bonus are required' });
    }

    let updateQuery;
    let queryParams;

    if (id === 0) {
        updateQuery = `
            UPDATE commission
            SET 
                direct_bonus = ?,
                indirect_bonus = ?
            WHERE id = 0`;
        queryParams = [direct_bonus, indirect_bonus];
    } else {
        updateQuery = `
            UPDATE commission
            SET 
                direct_bonus = ?,
                indirect_bonus = ?
            WHERE id = ?`;
        queryParams = [direct_bonus, indirect_bonus, id];
    }


    con.query(updateQuery, queryParams, (err, result) => {
        if (err) {
            console.error('Error updating commission data:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update commission data' });
        }


        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'Commission data not found' });
        }

        res.json({ status: 'success', message: 'Commission data updated successfully' });
    });
});

app.put('/bonus-settings/:id', (req, res) => {
    const settingId = req.params.id;
    const { need_refferer, reward } = req.body;

    const updateSettingQuery = `
        UPDATE bonus_settings
        SET need_refferer = ?, reward = ?
        WHERE id = ?
    `;

    con.query(updateSettingQuery, [need_refferer, reward, settingId], (err, result) => {
        if (err) {
            console.log(err);
            return res.status(500).json({ status: 'error', error: 'Failed to update bonus setting' });
        }

        res.json({ status: 'success', message: 'Bonus setting updated successfully' });
    });
});
app.get('/bonus-settings', (req, res) => {
    const fetchSettingsQuery = 'SELECT * FROM bonus_settings';

    con.query(fetchSettingsQuery, (err, result) => {
        if (err) {
            return res.status(500).json({ status: 'error', error: 'Failed to fetch bonus settings' });
        }

        // If data fetched successfully, return it in the response
        res.json({ status: 'success', data: result });
    });
});

app.put('/updateWithdrawData', (req, res) => {
    const { id, min, max, level } = req.body;

    if (!min || !max || !level) {
        return res.status(400).json({ status: 'error', message: 'Min Team, Max Team, and Level are required' });
    }

    let updateQuery = `
        UPDATE withdraw_limit

        SET 
            min = ?,
            max = ?,
            level = ?
        WHERE id = ?`;
    let queryParams = [min, max, level, id];


    con.query(updateQuery, queryParams, (err, result) => {
        if (err) {
            console.error('Error updating level data:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update level data' });
        }


        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'Level data not found' });
        }

        res.json({ status: 'success', message: 'Level data updated successfully' });
    });
});

app.put('/updateLevelData', (req, res) => {
    const { id, min_team, max_team, level } = req.body;

    if (!min_team || !max_team || !level) {
        return res.status(400).json({ status: 'error', message: 'Min Team, Max Team, and Level are required' });
    }

    let updateQuery = `
        UPDATE levels
        SET 
            min_team = ?,
            max_team = ?,
            level = ?
        WHERE id = ?`;
    let queryParams = [min_team, max_team, level, id];


    con.query(updateQuery, queryParams, (err, result) => {
        if (err) {
            console.error('Error updating level data:', err);
            return res.status(500).json({ status: 'error', error: 'Failed to update level data' });
        }


        if (result.affectedRows === 0) {
            return res.status(404).json({ status: 'error', message: 'Level data not found' });
        }

        res.json({ status: 'success', message: 'Level data updated successfully' });
    });
});

app.get('/receive-accounts', (req, res) => {
    const status = 'on'; // Define the status you're looking for
    const sql = 'SELECT * FROM accounts WHERE status = ? LIMIT 1';

    con.query(sql, [status], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching accounts.' });
        }

        if (result.length > 0) {
            res.status(200).json({ success: true, account: result[0] });
        } else {
            res.status(404).json({ success: false, message: 'No account found with the given status.' });
        }
    });
});

app.get('/pending-users', (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 10;
    const searchTerm = req.query.searchTerm || '';

    const offset = (page - 1) * perPage;

    let sql = 'SELECT * FROM users WHERE payment_ok = 0 AND approved = 0';

    if (searchTerm) {
        sql += ` AND (name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%' OR id = '${searchTerm}')`;
    }

    sql += ` LIMIT ? OFFSET ?`;

    const countSql = `SELECT COUNT(*) AS totalCount FROM users WHERE payment_ok = 0 AND approved = 0 ${searchTerm ? `AND (name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%' OR id = '${searchTerm}')` : ''}`;

    con.query(sql, [perPage, offset], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the pending users.' });
        }

        con.query(countSql, (countErr, countResult) => {
            if (countErr) {
                return res.status(500).json({ success: false, message: 'An error occurred while fetching total count.' });
            }

            const totalCount = countResult[0].totalCount;

            res.status(200).json({
                success: true,
                pendingUsers: result,
                totalCount: totalCount,
                currentPage: page,
                totalPages: Math.ceil(totalCount / perPage)
            });
        });
    });
});


app.delete('/delete-user/:id', (req, res) => {
    const userId = req.params.id;
    const sql = 'DELETE FROM users WHERE id = ?';

    con.query(sql, [userId], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while deleting the user.' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ success: true, message: 'User deleted successfully.' });
        } else {
            res.status(404).json({ success: false, message: 'User not found.' });
        }
    });
});
app.delete('/delete-7-days-old-users', (req, res) => {
    const sql = `
        DELETE FROM users 
        WHERE payment_ok=0 AND approved=0 AND created_at <= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
    `;

    con.query(sql, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "An error occurred while deleting the users." });
        }

        res.status(200).json({ success: true, message: `${result.affectedRows} users deleted successfully.` });
    });
});

const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

app.post('/upload', upload.single('image'), (req, res) => {

    // File data
    const { filename, path: filePath, size } = req.file;
    const uploadTime = new Date();

    // Insert into database
    const query = 'INSERT INTO images (file_name, file_path, upload_time) VALUES (?, ?, ?)';
    const values = [filename, filePath, uploadTime];

    con.query(query, values, (error, results, fields) => {
        if (error) throw error;

        res.json({ message: 'File uploaded and data saved successfully' });
    });
});
app.get('/getImage', (req, res) => {
    const query = 'SELECT * FROM images ORDER BY upload_time DESC LIMIT 1';

    con.query(query, (error, results, fields) => {
        if (error) {
            console.error(error);
            return res.status(500).json({ error: 'An error occurred while fetching image data' });
        }

        if (results.length > 0) {
            res.json(results[0]);
        } else {
            res.status(404).json({ message: 'No images found' });
        }
    });
});

app.post('/update-accounts', (req, res) => {
    const accounts = req.body.accounts;

    if (!accounts || !Array.isArray(accounts)) {
        return res.status(400).json({ success: false, message: 'Invalid account data.' });
    }

    accounts.forEach(account => {
        if (account.account_id) {
            const sql = 'UPDATE accounts SET account_name = ?, account_number = ?, status = ? WHERE account_id = ?';
            const values = [account.account_name, account.account_number, account.status, account.account_id];

            con.query(sql, values, (err) => {
                if (err) {
                    console.error('Failed to update account:', err);
                }
            });
        } else {
            console.error('Account ID is NULL, skipping update.');
        }
    });

    res.json({ success: true, message: 'Accounts updated successfully.' });
});




app.get('/get-total-withdrawal', (req, res) => {
    // SQL query to sum all amounts in the withdrawal_requests table
    const sql = 'SELECT SUM(amount) AS totalWithdrawal FROM withdrawal_requests';

    con.query(sql, (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: 'An error occurred while fetching the total withdrawal.' });
        }

        if (result.length === 0) {
            return res.status(404).json({ success: false, message: 'No withdrawal requests found.' });
        }

        res.status(200).json({ success: true, totalWithdrawal: result[0].totalWithdrawal });
    });
});
app.delete('/delete-old-rejected-users', (req, res) => {
    // Calculate the date 7 days ago from the current date
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const deleteOldRejectedUsersSql = `
        DELETE FROM users
        WHERE rejected = 1 AND rejected_at < ?`;

    con.query(deleteOldRejectedUsersSql, [sevenDaysAgo], (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        res.json({ message: 'Old rejected user records deleted successfully' });
    });
});
app.delete('/delete-rejected-users', (req, res) => {
    const deleteRejectedUsersSql = `
        DELETE FROM users
        WHERE rejected = 1`;

    con.query(deleteRejectedUsersSql, (error, results) => {
        if (error) {
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results.affectedRows === 0) {
            return res.json({ message: 'No rejected users to delete' });
        }

        res.json({ message: 'Rejected users deleted successfully' });
    });
});



app.get('/dashboard-data', (req, res) => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(today.getDate() + 1);

    const sql = `
        SELECT 
            (SELECT COUNT(*) FROM users WHERE approved = 1) as approvedUsersCount,
            (SELECT COUNT(*) FROM users WHERE approved = 1 AND approved_at >= ? AND approved_at < ?) as approvedUsersCountToday,
            (SELECT SUM(amount) FROM withdrawal_requests where approved='approved') as totalWithdrawal ,
            (SELECT SUM(amount) FROM withdrawal_requests WHERE DATE(approved_time) = CURDATE()) as totalAmountToday,
            (SELECT COUNT(*) FROM users WHERE payment_ok = 0 AND approved = 0) as unapprovedUnpaidUsersCount,
            (SELECT SUM(amount) as total_amount FROM withdrawal_requests WHERE DATE(approved_time) = CURDATE()) as totalAmountTodayWithdrawal,
            (SELECT SUM(jf.joining_fee * (SELECT COUNT(*) FROM users WHERE approved = 1)) FROM joining_fee jf) as totalReceived,
            (SELECT SUM(jf.joining_fee * (SELECT COUNT(*) FROM users WHERE approved = 1 AND approved_at >= ? AND approved_at < ?)) FROM joining_fee jf) as totalReceivedToday,
            (SELECT SUM(backend_wallet) from users WHERE approved=1) as backend_wallet,
            (SELECT sum(balance) from users WHERE approved=1) as balance,
            (SELECT sum(amount) from bonus_history ) as bonus,
            (SELECT sum(amount) from week_bonus_history) as total_salary,

            
            ( SELECT
        ((SELECT joining_fee FROM joining_fee WHERE id = 1) / 100) * 
        (
            (SELECT SUM(direct_bonus + indirect_bonus) FROM commission)
           
            
                
        +
           (SELECT initial_percent from initial_fee)

            ) * (SELECT count(*) from users WHERE approved=1) 
                    + (SELECT SUM(amount) FROM bonus_history) +
                    (SELECT SUM(amount) FROM week_bonus_history)

) as will_give
        



    `;

    con.query(sql, [today, tomorrow, today, tomorrow], (err, results) => {
        if (err) {
            console.log(err);

            return res.status(500).json({ success: false, message: 'An error occurred while fetching dashboard data.' });
        }

        const dashboardData = {
            approvedUsersCount: results[0].approvedUsersCount,
            approvedUsersCountToday: results[0].approvedUsersCountToday,
            totalWithdrawal: results[0].totalWithdrawal,
            totalAmountToday: results[0].totalAmountToday,
            unapprovedUnpaidUsersCount: results[0].unapprovedUnpaidUsersCount,
            totalAmountTodayWithdrawal: results[0].totalAmountTodayWithdrawal,
            totalReceived: results[0].totalReceived,
            totalReceivedToday: results[0].totalReceivedToday,
            backend_wallet: results[0].backend_wallet,
            users_balance: results[0].balance,
            users_bonus: results[0].bonus,
            todayIncome: (results[0].totalReceivedToday) - (results[0].totalAmountTodayWithdrawal),
            totalIncome: results[0].totalReceived - results[0].totalWithdrawal,
            totalSalary: results[0].total_salary,
            will_give: results[0].will_give - results[0].totalWithdrawal,


        };
        console.log(dashboardData);

        res.status(200).json({ success: true, dashboardData });
    });
});



app.listen(PORT, () => {
    console.log('HTTPS Server running on port ' + PORT);
});
