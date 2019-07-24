import React, { Component } from 'react';
class ProfileGithub extends Component {
  constructor(props){
    super(props);
    this.state = {
      clientId: 'ae6a122475b65bc464fa',
      cilentSecret: '322e07c50cbf09e0abc54933c699c73facea41b4',
      count: 5,
      sort: 'created: asc',
      repos: []
    }
  }
  componentDidMount(){
    const { username } = this.props;
    const { clientId, clientSecret, count, sort} = this.state;
    fetch(`https://api.github.com/users/${username}/repos?per_page=${count}
    &sort=${sort}&client_id=${clientId}&client_secret=${clientSecret}`)
    .then(res => res.json())
    .then(data => {
      this.setState({
        repos: data
      })
    })
    .catch(err => console.log(err));
  }
  render() {
    const {repos} = this.state;
    const reposItems = repos.map(repo => {
      return(
        <div 
        className="card card-body mb-2"
        key={repo.id}>
        <div className="row">
          <div className="col-md-6">
            <h4>
              <a href={repo.html_url} className='text-info' target='__blank'>
                {repo.name}
              </a>
            </h4>
          </div>
          <div className="col-md-6">
            <span className="badge badge-info mr-2">
              Stars: {repo.stargazers_count}
            </span>
            <span className="badge badge-secondary mr-2">
              Watches: {repo.watchers_count}
            </span>
            <span className="badge badge-success">
              Forks: {repo.forks_count}
            </span>
          </div>
        </div>

        </div>
      )
    })
    return (
      <div>
        <h3 className='mb-4'>Latest Github Repos</h3>
          {reposItems}
      </div>
    )
  }
}
export default ProfileGithub;
