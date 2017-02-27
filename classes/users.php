<?php
// manage users
class User {
    private $user_table = "sf_user";

    // validate email exists in database
    public function validate_email($email) {
        global $sf_database;

        // create sql
        $select_email = 'SELECT email FROM ' .  $this->user_table . ' WHERE email = :email LIMIT 1';
        $email_array = array(
            ':email'   => $email
        );
        $sf_database->run_query($select_email, $email_array);
        $user = $sf_database->return_results(true);

        // if email already exists, return false.
        if($user) {
            return false;
        } else {
            // otherwise, the email does not exist in the database
            return true;
        }
    }

    // validates password to make sure
    public function validate_password($password) {
        if(!preg_match('/^(?=.*\d)(?=.*[A-Za-z])[0-9A-Za-z!@#$%]{8,12}$/', $password)) {
            return false;
        } else {
            return true;
        }
    }

    private function encrypt_password($password) {
        $cost = 10;
        $salt = strtr(base64_encode(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM)), '+', '.');
        $salt = sprintf("$2a$%02d$", $cost) . $salt;

        // hash password
        $hash = crypt($password, $salt);
        return $hash;
    }

    public function reset_password($email, $password) {
        global $sf_database;

        // encrypt password
        $password_hash = $this->encrypt_password($password);

        $reset_password = 'UPDATE ' .  $this->user_table . ' SET password = :password WHERE email = :email';
        $reset_password_array = array(
            ':password' => $password_hash,
            ':email' => $email
        );
        $sf_database->run_query($reset_password, $reset_password_array);
        return $sf_database->query_success;
    }

    public function create_user($email, $password) {
        global $sf_database;

        // encrypt password
        $password_hash = $this->encrypt_password($password);

        // create sql
        $insert_new_user = 'INSERT INTO ' .  $this->user_table . ' (email, password)
VALUES (:email, :password)';
        $new_user_array = array(
            ':email'        => $email,
            ':password'     => $password_hash
        );
        $sf_database->run_query($insert_new_user, $new_user_array);

        return $sf_database->query_success;
    }

    // verify that the user exists in the table
    public function verify_user($email, $password) {
        global $sf_database;

        // create sql
        $select_email = 'SELECT * FROM ' .  $this->user_table . ' WHERE email = :email LIMIT 1';
        $email_array = array(
            ':email'   => $email
        );
        $sf_database->run_query($select_email, $email_array);

        // if query ran successfully
        if( $sf_database->query_success ) {
            // then validate password
            $user = $sf_database->return_results(true);

            // if results exist
            if($user) {
                // Hashing the password with its hash as the salt returns the same hash
                if ( hash_equals($user['password'], crypt($password, $user['password'])) ) {
                    return $user;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

}

$sf_user = new User();