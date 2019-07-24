import React from 'react';
import { connect } from 'react-redux';
import { Link } from 'react-router-dom';
import suitperson from '../suitperson.jpg';
import { likePost, unlikePost, deletePost, addComment, deleteComment } from '../../actions/postActions';
import './postItem.css';
class PostItem extends React.Component{
    constructor(props){
        super(props);
        console.log('Props', props);
        this.state = {
            likeMark: props.postItem.likes.findIndex(like => like.user === props.auth.user.id ),
            post: props.postItem,
            auth: props.auth,
            showComments: false
        }
    }
    componentWillReceiveProps(nextProps){
        console.log('next Props', nextProps);
        if(nextProps.post && nextProps.post._id === this.props.postItem._id){
            this.setState({
                post: nextProps.post,
                likeMark: nextProps.post.likes.findIndex(like => like.user === this.props.auth.user.id )
            })
        }
        else if(nextProps.postItem)
            this.setState({
                likeMark: nextProps.postItem.likes.findIndex(like => like.user === nextProps.auth.user.id ),
                post: nextProps.postItem,
                auth: nextProps.auth
            })
    }
    likeClicked = () => {
        if(this.state.likeMark === -1){
            this.props.likePost(this.state.post._id);
        }
        else{
            this.props.unlikePost(this.state.post._id);
        }
    }
    commentClicked = () => {
        this.setState({
            showComments: !this.state.showComments
        })
    }
    submitComment = (e) => {
        e.preventDefault();
        const text = document.getElementById('comment_input_id').value;
        this.props.addComment(this.state.post._id, {text});
    }
    deletePost = () => {
        this.props.deletePost(this.state.post._id);
    }
render(){
    const { post, likeMark, auth, showComments } = this.state;
    const comments = showComments?(
        <div className="comments">
            {this.state.post.comments.map((item, index) => {
               return(
                   <div 
                   style={{
                       border: '1px solid silver'
                   }}
                   className="comment my-3 p-2 row"
                   key={index}>
                   <Link 
                   style={{
                       height: 'fit-content'
                   }}
                   to='anything' className=''>{item.user.name}</Link>
                   <span className='col-md-auto'>{item.text}</span>
                   {auth.user.id === item.user._id?(
                       <button
                       style={{
                           height: '40px'
                       }}
                       className='btn btn-danger col-md-3 ml-auto' 
                       onClick={(e) => {
                           this.props.deleteComment(this.state.post._id, item._id)
                       }}
                       >Remove</button>
                   ):null}
                   </div>
               )
            })}
            {this.state.post.comments.length === 0? (
                <div className="alert alert-danger text-center p-2 m-2">
                    There is no comments Yet
                </div>
            ):null}
            <form 
                onSubmit={this.submitComment}
                className="row">
                    <div className="input-group">
                        <input 
                        id='comment_input_id'
                        type="text" 
                        className="form-control col-md-8" required/>
                        <div className="col-md-4">
                        <input type='submit' value='Add Comment' className='btn btn-primary' />
                        </div>
                    </div>
                </form>
        </div>
    ):null;
    return (
        <div 
        className='post'
        style={{
            minHeight: '100px',
            // background: '#EEE',
            // borderRadius: '10px',
            border: '1px solid #DDD',
            padding: '10px',
            margin: '10px 0'
        }}>
          <img 
          src={suitperson} 
          alt='User_image' 
          width='30px'
          height='30px'
          className='mr-2' />
          <Link to={`/posts`}>{post.name}</Link>
          <pre
          className='lead'
          style={{
              textIndent: '50px'
          }}>{post.text}</pre>
          <div className="row pl-5">
            <div className='actions col-md-10'>
                <button 
                className="like col-md-3 mr-1 text-center p-2 btn btn-light"
                onClick={this.likeClicked}
                style={{
                    cursor: 'pointer'
                }}>
                    {likeMark===-1?(
                        <i className="far fa-thumbs-up mr-2"></i>
                    ): (<i className="fas fa-thumbs-up mr-2 text-primary"></i>)}
                    <span>{post.likes.length}</span>
                </button>
                <Link 
                to={`/post/${post._id}`}
                className="comments btn btn-secondary text-center col-md-3 mr-1 p-2">
                        Comments
                </Link>
                {auth.user.id === post.user._id?(
                    <button 
                    onClick={this.deletePost}
                    className="comments btn btn-danger text-center col-md-3 mr-1 p-2">
                        Remove
                    </button>
                ):null}
                {comments}
                
            </div>
          </div>
        </div>
      )
}
}
const mapStateToProps = (state) => (
    {
        post: state.post.post,
        errors: state.errors,
    }
)
export default connect(mapStateToProps, { likePost, unlikePost, deletePost, addComment, deleteComment })(PostItem);
