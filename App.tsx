import React, { useState } from 'react';
import axios from 'axios';
import { BrowserRouter as Router, Switch, Route, Link } from 'react-router-dom';

const BASE_URL = 'http://localhost:3000';

const LoginForm: React.FC<{ handleLogin: (token: string) => void }> = ({ handleLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = (e: React.FormEvent) =>
  {
    e.preventDefault();
    axios.post('${BASE_URL}/login', { username, password })
    .then((response) => {
    handleLogin(response.data.token);
    })
    .catch((error) => {
    console.error(error);
    });
    };
    
    return (
    <form onSubmit={handleSubmit}>
    <input
    type="text"placeholder="Username"
    value={username}
    onChange={(e) => setUsername(e.target.value)}
    />
    <input
    type="password"
    placeholder="Password"
    value={password}
    onChange={(e) => setPassword(e.target.value)}
    />
    <button type="submit">Login</button>
    </form>
    );
    };
    
    interface User {_id: string;
        username: string;
        }
        
        const UserList: React.FC<{ users: User[] }> = ({ users }) => (
        
          <div>
            <h2>User List</h2>
            <ul>
              {users.map((user) => (
                <li key={user._id}>{user.username}</li>
              ))}
            </ul>
          </div>
        );
        const App: React.FC = () => {
        const [token, setToken] = useState('');
        const [users, setUsers] = useState<User[]>([]);

const handleLogin = (token: string) => {
setToken(token);
axios.get('${BASE_URL}/users', {
headers: {
Authorization: Bearer ${token},
},
})
.then((response) => {
setUsers(response.data);
})
.catch((error) => {
console.error(error);
});
};

return (
<Router>
<div>
<nav>
<ul>
<li>
<Link to="/">Home</Link>
</li>
<li>
<Link to="/users">Users</Link>
</li>
</ul>
</nav>
<Switch>
      <Route exact path="/">
        {token ? (
          <h1>Welcome!</h1>
        ) : (
          <LoginForm handleLogin={handleLogin} />
        )}
      </Route>
      <Route path="/users">
        {token ? (
          <UserList users={users} />
        ) : (
          <h1>Please log in to view this page</h1>
        )}
      </Route>
    </Switch>
  </div>
</Router>
);
};


# In the frontend directory:
#npm start

# In the backend directory:
#npm run start:backend
