import React, { Component } from 'react'
import { connect } from 'react-redux';
import { withRouter } from 'react-router-dom';
import classnames from 'classnames';
import { addPost } from '../../actions/postActions';
class PostForm extends Component {
  constructor(props){
    super(props);
    this.state = {
      text: '',
      errors: {}
    }
  }
  componentWillReceiveProps(nextProps){
    if(nextProps.errors){
      this.setState({
        errors: nextProps.errors
      })
    }
  }
  changed = (e) => {
    this.setState({
      [e.target.name]: e.target.value
    })
  }
  submit = (e) => {
    e.preventDefault();
    const { user } = this.props.auth;
    const newPost = {
      text: this.state.text,
      name: user.name,
      email: user.email
    }
    console.log(newPost);
    this.props.addPost(newPost, this.props.history);
  }
  render() {
    const {text, errors } = this.state;
    let borderColor = null;
    if(errors.text)
      borderColor = 'red';
    return (
      <div className="row">
        <form onSubmit={this.submit} className="col-md-6 m-auto p-5">
          <div className="form-group mb-2">
          <textarea 
          style={{
            borderColor
          }}
          name='text'
          value={text}
          placeholder='Enter Post... '
          onChange={this.changed}
          className= {classnames("form-control", {
            'is-invalid': errors[text],
            })}
          />
          {errors.text?(<small className='text-danger'>{errors.text}</small>): null}
          </div>
          <input type='submit' value='Add Post'
          className='btn btn-block btn-success text-center'
          />
        </form>
      </div>
    )
  }
}
const maptStateToProps = state => (
  {
    auth  : state.auth,
    errors: state.errors
  }
)
export default connect(maptStateToProps, { addPost })(withRouter(PostForm));
