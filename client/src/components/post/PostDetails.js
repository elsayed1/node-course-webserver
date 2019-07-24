import React, { Component } from 'react';
import { Link } from 'react-router-dom';
import { connect } from 'react-redux';
import { getPost, addComment, deleteComment } from '../../actions/postActions';
import Loading from '../common/Loading';
class PostDetails extends Component {
    constructor(props){
        super(props);
        this.state = {
            post: null,
            errors: {}
        }
    }
    componentDidMount(){
        console.log(this.props);
        this.props.getPost(this.props.match.params.post_id)
    }
    componentWillReceiveProps(nextProps){
        if(nextProps.post){
            this.setState({
                post: nextProps.post
            })
        }
        if(nextProps.errors){
            this.setState({
                errors: nextProps.errors
            })
        }
    }
    addComment = (e) => {
        e.preventDefault();
        const comment = this.refs.comment.value.trim();
        if(comment.length === 0)
            this.setState({
                errors: {
                    nocomment: 'Comment field is required'
                }
            })
        else{
            this.props.addComment(this.state.post._id, comment);
            this.refs.comment.value = '';
        }
    }
    render() {
        const { post, errors } = this.state;
        console.log(post);
        if(errors.nopost){
            return(
                <div className="alert alert-danger p-2 text-center">
                    {errors.nopost}
                </div>
            )
        }else if(post === null){
            return (<Loading />)
        }
        return (
            <div className='post p-5'>
                <div className="container w-75 mx-auto">
                    <Link to='/posts' >{post.name}</Link>
                    <pre className='ml-5 lead'>{post.text}</pre>
                    <div className="comments">
                        <hr/>
                        <h2 className="text-center"> Comments </h2>
                        <hr/>
                        {post.comments.map(comment => (
                           <div 
                           key={comment._id}
                           className="comment p-2">
                               <Link to='/posts'>{comment.user.name}</Link>
                               <div
                               style={{
                                   position: 'relative'
                               }}
                               >
                               <pre className='ml-5 lead'>{comment.text}</pre>
                               {String(this.props.user.id)===String(comment.user._id) ||
                               String(this.props.user.id) === String(post.user._id)?
                                <button 
                                style={{
                                    position: 'absolute',
                                    bottom: '5px',
                                    right: '10px'
                                }}
                                onClick={e => window.confirm('Are sure to delete comment')?this.props.deleteComment(post._id, comment._id):null }
                                className='btn btn-outline-danger '>Remove</button>:null}
                               </div>
                            <hr/>
                           </div>
                        ))}
                        <form 
                        onSubmit={this.addComment}>
                            <input
                            className='form-control my-1'
                            type='text' 
                            ref="comment"
                            placeholder='Write a comment'/>
                            {/* <input type='submit' class='btn btn-primary' /> */}
                        </form>
                    </div>
                </div>
            </div>
        )
    }
}
const mapStateToProps = state => ({
    post: state.post.post,
    errors: state.errors,
    user: state.auth.user
})
export default connect(mapStateToProps, { getPost, addComment, deleteComment })(PostDetails);