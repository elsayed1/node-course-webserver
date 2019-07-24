import React, { Component } from 'react';
import { connect } from 'react-redux';
import { getPosts } from '../../actions/postActions';
import Loading from '../common/Loading';
import PostItem from './PostItem';
class Posts extends Component {
  constructor(props){
      super(props);
      this.state = {
          posts: null,
          errors: null
      }
  }
  componentDidMount(){
    this.props.getPosts();
  }
  componentWillReceiveProps(nextProps){
    if(nextProps.errors)
        this.setState({
            errors: nextProps.errors
        })
    else if(nextProps.posts)
        this.setState({
            posts: nextProps.posts
        })
  }
  render() {
    const { posts } = this.state;
    console.log('Posts', posts);
    if(posts === null)
        return (<Loading />)
    else if(posts.length === 0)
        return (
            <div className="container">
                <div className="alert alert-danger text-center mt-3">
                    There is no posts yet
                </div>
            </div>
        )
    else{
        const postsItems = posts.map((item, index) => {
            return(
                <PostItem 
                key={index}
                auth={this.props.auth}
                postItem={item}
                />
            )
        })
        return (
            <div className="posts">
                <div className="row">
                    <div className="col-md-8 m-auto">
                        {postsItems}
                    </div>
                </div>
            </div>
          )
    }
  }
}
const mapStateToProps = (state) => (
    {
        auth : state.auth,
        posts: state.post.posts
    }
)
export default connect(mapStateToProps, { getPosts })(Posts);
